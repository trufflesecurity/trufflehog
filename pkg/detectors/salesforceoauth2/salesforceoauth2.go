package salesforceoauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	instancePat       = regexp.MustCompile(`\b(?:https?://)?([0-9a-zA-Z\-\.]{1,100}\.my\.salesforce\.com)\b`)
	consumerKeyPat    = regexp.MustCompile(`\b(3MVG9[0-9a-zA-Z._+/=]{80,251})`)
	consumerSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"salesforce", "consumer", "secret"}) + `\b([A-Za-z0-9+/=.]{64}|[0-9]{19})\b`)

	invalidHosts = simple.NewCache[struct{}]()
	errNoHost    = errors.New("no such host")
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"salesforce", "3MVG9"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SalesforceOauth2
}

func (s Scanner) Description() string {
	return "Salesforce is a customer relationship management (CRM) platform that provides a suite of applications and a platform for custom development. Its APIs use OAuth 2.0, and credentials like the Consumer Key and Secret are used to grant applications access to an organization's data."
}

// FromData will find and optionally verify Salesforceoauth2 secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueInstanceMatches, uniqueKeyMatches, uniqueSecretMatches := make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})
	for _, match := range instancePat.FindAllStringSubmatch(dataStr, -1) {
		uniqueInstanceMatches[match[1]] = struct{}{}
	}

	for _, match := range consumerKeyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeyMatches[match[1]] = struct{}{}
	}

	for _, match := range consumerSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecretMatches[match[1]] = struct{}{}
	}

	// If we are missing any of the three components, we cannot form a valid credential.
	if len(uniqueInstanceMatches) == 0 || len(uniqueKeyMatches) == 0 || len(uniqueSecretMatches) == 0 {
		return nil, nil
	}

domainLoop:
	for domain := range uniqueInstanceMatches {
		if invalidHosts.Exists(domain) {
			continue domainLoop
		}

		for key := range uniqueKeyMatches {
			for secret := range uniqueSecretMatches {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_SalesforceOauth2,
					Raw:          []byte(secret),
					RawV2:        fmt.Appendf([]byte{}, "%s:%s:%s", domain, key, secret),
				}

				if verify {
					isVerified, verificationErr := s.verifyMatch(ctx, s.getClient(), domain, key, secret)
					s1.Verified = isVerified
					if verificationErr != nil {
						if errors.Is(verificationErr, errNoHost) {
							invalidHosts.Set(domain, struct{}{})
							continue domainLoop
						}

						s1.SetVerificationError(verificationErr, secret)
					}
				}

				results = append(results, s1)
			}
		}
	}

	return
}

// verifyMatch attempts to validate a Salesforce Client Credentials pair.
func (s Scanner) verifyMatch(ctx context.Context, client *http.Client, domain, key, secret string) (bool, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", key)
	form.Set("client_secret", secret)

	authURL := fmt.Sprintf("https://%s/services/oauth2/token", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return false, errNoHost
		}

		return false, fmt.Errorf("failed to perform request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusBadRequest:
		return s.handleBadRequest(resp)
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

// Reusable error response struct
type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// handleBadRequest processes 400 responses to determine if credentials are invalid or misconfigured
func (s Scanner) handleBadRequest(resp *http.Response) (bool, error) {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read error response body: %w", err)
	}

	var errorResponse oauthErrorResponse
	if err := json.Unmarshal(bodyBytes, &errorResponse); err != nil {
		return false, fmt.Errorf("failed to unmarshal error response: %w (body: %s)", err, string(bodyBytes))
	}

	switch errorResponse.Error {
	case "invalid_client_id", "invalid_client":
		// This definitively means the key is invalid
		// Or the key is valid but the secret is wrong.
		return false, nil
	case "invalid_grant":
		// This can mean the secret is wrong OR the user isn't configured with the app secret.
		// We'll treat it as a VerificationError because the key might be valid but misconfigured.
		return false, fmt.Errorf("verification failed: %s", errorResponse.ErrorDescription)
	default:
		return false, fmt.Errorf("unexpected OAuth error: %s - %s", errorResponse.Error, errorResponse.ErrorDescription)
	}
}
