package gitlaboauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.EndpointSetter
	detectors.DefaultMultiPartCredentialProvider
}

func (Scanner) CloudEndpoint() string { return "https://gitlab.com" }

var (
	// Ensure the Scanner satisfies the interfaces at compile time.
	_ detectors.Detector                    = (*Scanner)(nil)
	_ detectors.EndpointCustomizer          = (*Scanner)(nil)
	_ detectors.MultiPartCredentialProvider = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()
	clientIdPat   = regexp.MustCompile(
		detectors.PrefixRegex([]string{"application_id", "client_id", "app_id", "id"}) + `\b([0-9a-f]{64})\b`)
	clientSecretPat = regexp.MustCompile(`\b(gloas-[0-9a-f]{64})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"gloas-"}
}

// FromData will find and optionally verify GitLab OAuth secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueIdMatches := make(map[string]struct{})
	for _, match := range clientIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueIdMatches[match[1]] = struct{}{}
	}

	uniqueSecretMatches := make(map[string]struct{})
	for _, match := range clientSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecretMatches[match[1]] = struct{}{}
	}

	for clientId := range uniqueIdMatches {
	secretLoop:
		for clientSecret := range uniqueSecretMatches {
			for _, endpoint := range s.Endpoints() {
				s1 := detectors.Result{
					DetectorType: s.Type(),
					Raw:          []byte(clientSecret),
					RawV2:        []byte(clientId + clientSecret + endpoint),
					SecretParts: map[string]string{
						"client_id":     clientId,
						"client_secret": clientSecret,
						"endpoint":      endpoint,
					},
				}

				if verify {
					isVerified, verificationErr := verifyMatch(
						ctx, s.getClient(), endpoint, clientId, clientSecret,
					)
					s1.Verified = isVerified
					s1.SetVerificationError(verificationErr)

					if s1.Verified {
						// A client_id is bound to a single secret; skip remaining
						// endpoints and secrets for this client_id.
						results = append(results, s1)
						break secretLoop
					}
				}

				results = append(results, s1)
			}
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, endpoint string, clientId string, clientSecret string) (bool, error) {
	url := endpoint + "/oauth/token"
	payload := strings.NewReader("grant_type=client_credentials&client_id=" + clientId +
		"&client_secret=" + clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payload)
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// We use grant_type=client_credentials which GitLab doesn't support for OAuth apps,
	// so even valid credentials never return 200. Instead, GitLab validates credentials
	// before checking grant type:
	//
	// - 400 with "invalid_scope": credentials are valid (grant type rejected after auth passed)
	// - 401 with "invalid_client": credentials are invalid
	//
	// Any other status (e.g. 422 for apps with `api` scope) is treated as inconclusive
	// since we cannot determine credential validity, and falls through to the default case.
	switch res.StatusCode {
	case http.StatusBadRequest:
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}

		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
			return false, err
		}

		if errResp.Error == "invalid_scope" {
			return true, nil
		}

		return false, fmt.Errorf("unexpected error in response: %s", errResp.Error)

	case http.StatusUnauthorized:
		return false, nil

	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_GitLabOauth2
}

func (s Scanner) Description() string {
	return "GitLab is a web-based DevOps lifecycle tool that provides a Git repository manager providing wiki, issue-tracking, and CI/CD pipeline features. GitLab OAuth application credentials can be used to access GitLab APIs on behalf of users."
}
