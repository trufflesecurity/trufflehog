package dockerhub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

func (s Scanner) Version() int { return 1 }

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var (
	// Can use email or username for login.
	usernamePat = regexp.MustCompile(detectors.PrefixRegex([]string{"docker"}) + `(?im)(?:user|usr|username|-u|id)\s{0,40}?[:=\s]{1,3}[ '"=]?([a-zA-Z0-9][a-zA-Z0-9_-]{3,39})\b`)
	emailPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"docker"}) + common.EmailPattern)

	// Can use password or personal access token (PAT) for login, but this scanner will only check for PATs.
	accessTokenPat = regexp.MustCompile(`(?i)(?:docker[-_]?(?:token|pat|password|access[-_]?token))\s{0,10}?[:=\s]{1,3}[ '"=]?([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`)

	// Pattern to exclude Docker protocol headers
	excludeHeaderPat = regexp.MustCompile(`(?i)(?:docker[-_]?upload[-_]?uuid|x[-_]?docker[-_]?upload[-_]?uuid|docker[-_]?content[-_]?digest)\s*:\s*([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"docker"}
}

// FromData will find and optionally verify Dockerhub secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// First, find and exclude Docker protocol headers to avoid false positives
	excludedTokens := make(map[string]struct{})
	for _, matches := range excludeHeaderPat.FindAllStringSubmatch(dataStr, -1) {
		excludedTokens[matches[1]] = struct{}{}
	}

	// Deduplicate results and filter out excluded tokens.
	tokens := make(map[string]struct{})
	for _, matches := range accessTokenPat.FindAllStringSubmatch(dataStr, -1) {
		// Skip if this token was found in a Docker protocol header
		if _, excluded := excludedTokens[matches[1]]; !excluded {
			tokens[matches[1]] = struct{}{}
		}
	}
	if len(tokens) == 0 {
		return
	}

	usernames := make(map[string]struct{})
	for _, matches := range usernamePat.FindAllStringSubmatch(dataStr, -1) {
		// Additional validation: ensure username doesn't look like part of a UUID
		if !isLikelyUUIDFragment(matches[1]) {
			usernames[matches[1]] = struct{}{}
		}
	}
	for _, matches := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		usernames[matches[1]] = struct{}{}
	}

	// Process results.
	for token := range tokens {
		s1 := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(token),
		}

		for username := range usernames {
			s1.RawV2 = []byte(fmt.Sprintf("%s:%s", username, token))

			if verify {
				if s.client == nil {
					s.client = common.SaneHttpClient()
				}

				isVerified, extraData, verificationErr := s.verifyMatch(ctx, username, token)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr)
				if s1.Verified {
					s1.AnalysisInfo = map[string]string{
						"username": username,
						"pat":      token,
					}
				}
			}

			results = append(results, s1)

			if s1.Verified {
				break
			}
		}

		// PAT matches without usernames cannot be verified but might still be useful.
		if len(usernames) == 0 {
			results = append(results, s1)
		}
	}
	return
}

// Helper function to detect if a string looks like a UUID fragment
func isLikelyUUIDFragment(s string) bool {
	// Check if it's all digits (common in correlation IDs)
	if regexp.MustCompile(`^\d+$`).MatchString(s) {
		return true
	}
	// Check if it looks like the first part of a UUID (8 hex chars)
	if regexp.MustCompile(`^[a-f0-9]{8}$`).MatchString(strings.ToLower(s)) {
		return true
	}
	return false
}

func (s Scanner) verifyMatch(ctx context.Context, username string, password string) (bool, map[string]string, error) {
	payload := strings.NewReader(fmt.Sprintf(`{"identifier": "%s", "secret": "%s"}`, username, password))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hub.docker.com/v2/auth/token", payload)
	if err != nil {
		return false, nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	res, err := s.client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return false, nil, err
	}

	if res.StatusCode == http.StatusOK {
		var tokenRes tokenResponse
		if err := json.Unmarshal(body, &tokenRes); (err != nil || tokenRes == tokenResponse{}) {
			return false, nil, err
		}

		parser := jwt.NewParser()
		token, _, err := parser.ParseUnverified(tokenRes.AccessToken, &hubJwtClaims{})
		if err != nil {
			return true, nil, err
		}

		if claims, ok := token.Claims.(*hubJwtClaims); ok {
			extraData := map[string]string{
				"hub_username": username,
				"hub_email":    claims.HubClaims.Email,
				"hub_scope":    claims.Scope,
				"version":      fmt.Sprintf("%d", s.Version()),
			}
			return true, extraData, nil
		}
		return true, nil, nil
	} else if res.StatusCode == http.StatusUnauthorized {
		// Valid credentials can still return a 401 status code if 2FA is enabled
		var mfaRes mfaRequiredResponse
		if err := json.Unmarshal(body, &mfaRes); err != nil || mfaRes.MfaToken == "" {
			return false, map[string]string{"version": fmt.Sprintf("%d", s.Version())}, nil
		}

		extraData := map[string]string{
			"hub_username": username,
			"2fa_required": "true",
			"version":      fmt.Sprintf("%d", s.Version()),
		}
		return true, extraData, nil
	} else {
		return false, nil, fmt.Errorf("unexpected response status %d", res.StatusCode)
	}
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

type userClaims struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

type hubJwtClaims struct {
	Scope     string     `json:"scope"`
	HubClaims userClaims `json:"https://hub.docker.com"` // not sure why this is a key, further investigation required.
	jwt.RegisteredClaims
}

type mfaRequiredResponse struct {
	MfaToken string `json:"login_2fa_token"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Dockerhub
}

func (s Scanner) Description() string {
	return "Docker is a platform used to develop, ship, and run applications. Docker access tokens can be used to authenticate and interact with Docker services."
}
