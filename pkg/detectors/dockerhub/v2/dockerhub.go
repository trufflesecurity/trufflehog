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

func (s Scanner) Version() int { return 2 }

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var (
	// Can use email or username for login.
	// Docker ID must be between 4 and 30 characters long, and can only contain numbers and lowercase letters.
	// You can't use any special characters or spaces. https://docs.docker.com/admin/faqs/general-faqs/#what-is-a-docker-id
	usernamePat = regexp.MustCompile(detectors.PrefixRegex([]string{"docker"}) + `(?im)(?:user|usr|username|-u|id)(?:['"]?\s*[:=]\s*['"]?|[\s]+)([a-z0-9]{4,30})['"]?(?:\s|$|[,}])`)
	emailPat    = regexp.MustCompile(common.EmailPattern)

	// Can use password or personal/organization access token (PAT/OAT) for login, but this scanner will only check for PATs and OATs.
	accessTokenPat = regexp.MustCompile(`\b(dckr_pat_[a-zA-Z0-9_-]{27}|dckr_oat_[a-zA-Z0-9_-]{32})(?:[^a-zA-Z0-9_-]|\z)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"docker", "dckr_pat_", "dckr_oat_"}
}

// FromData will find and optionally verify Dockerhub secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Deduplicate results.
	tokens := make(map[string]struct{})
	for _, matches := range accessTokenPat.FindAllStringSubmatch(dataStr, -1) {
		tokens[matches[1]] = struct{}{}
	}
	if len(tokens) == 0 {
		return
	}
	usernames := make(map[string]struct{})
	for _, matches := range usernamePat.FindAllStringSubmatch(dataStr, -1) {
		usernames[matches[1]] = struct{}{}
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

				isVerified, extraData, verificationErr := VerifyMatch(ctx, s.client, username, token)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.ExtraData["version"] = fmt.Sprintf("%d", s.Version())
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

func VerifyMatch(ctx context.Context, client *http.Client, username string, password string) (bool, map[string]string, error) {
	payload := strings.NewReader(fmt.Sprintf(`{"identifier": "%s", "secret": "%s"}`, username, password))
	extraData := map[string]string{}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hub.docker.com/v2/auth/token", payload)
	if err != nil {
		return false, extraData, err
	}

	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return false, extraData, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return false, extraData, err
	}

	switch res.StatusCode {
	case http.StatusOK:
		var tokenRes tokenResponse
		if err := json.Unmarshal(body, &tokenRes); (err != nil || tokenRes == tokenResponse{}) {
			return false, extraData, err
		}

		parser := jwt.NewParser()
		token, _, err := parser.ParseUnverified(tokenRes.Token, &hubJwtClaims{})
		if err != nil {
			return true, extraData, err
		}

		if claims, ok := token.Claims.(*hubJwtClaims); ok {
			extraData = map[string]string{
				"hub_username": username,
				"hub_email":    claims.HubClaims.Email,
				"hub_scope":    claims.Scope,
			}
			return true, extraData, nil
		}
		return true, nil, nil
	case http.StatusUnauthorized:
		// Valid credentials can still return a 401 status code if 2FA is enabled
		var mfaRes mfaRequiredResponse
		if err := json.Unmarshal(body, &mfaRes); err != nil || mfaRes.MfaToken == "" {
			return false, extraData, nil
		}

		extraData = map[string]string{
			"hub_username": username,
			"2fa_required": "true",
		}
		return true, extraData, nil
	case http.StatusTooManyRequests:
		extraData = map[string]string{
			"verification": "rate_limited",
			"status_code":  "429",
			"retry_after":  res.Header.Get("X-Retry-After"),
		}

		return false, extraData, fmt.Errorf("rate limited (429) - verification unavailable")
	default:
		return false, nil, fmt.Errorf("unexpected response status %d", res.StatusCode)
	}
}

type tokenResponse struct {
	Token string `json:"access_token"`
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
	return "Dockerhub is a cloud-based repository in which Docker users and partners create, test, store and distribute container images. Dockerhub personal access tokens (PATs) can be used to access and manage these container images."
}
