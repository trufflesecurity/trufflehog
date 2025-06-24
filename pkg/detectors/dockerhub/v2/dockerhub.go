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
	usernamePat = regexp.MustCompile(`(?im)(?:user|usr|-u|id)\S{0,40}?[:=\s]{1,3}[ '"=]?([a-zA-Z0-9]{4,40})\b`)
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
		token, _, err := parser.ParseUnverified(tokenRes.Token, &hubJwtClaims{})
		if err != nil {
			return true, nil, err
		}

		if claims, ok := token.Claims.(*hubJwtClaims); ok {
			extraData := map[string]string{
				"hub_username": username,
				"hub_email":    claims.HubClaims.Email,
				"hub_scope":    claims.Scope,
			}
			return true, extraData, nil
		}
		return true, nil, nil
	} else if res.StatusCode == http.StatusUnauthorized {
		// Valid credentials can still return a 401 status code if 2FA is enabled
		var mfaRes mfaRequiredResponse
		if err := json.Unmarshal(body, &mfaRes); err != nil || mfaRes.MfaToken == "" {
			return false, nil, nil
		}

		extraData := map[string]string{
			"hub_username": username,
			"2fa_required": "true",
		}
		return true, extraData, nil
	} else {
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
