package salesforcerefreshtoken

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_             detectors.Detector = (*Scanner)(nil)
	defaultClient                    = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	refreshTokenPat   = regexp.MustCompile(`(?i)\b(5AEP861[a-zA-Z0-9._=]{80,})\b`)
	consumerKeyPat    = regexp.MustCompile(`\b(3MVG9[0-9a-zA-Z._+/=]{80,251})`)
	consumerSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"salesforce", "consumer", "secret"}) + `\b([A-Za-z0-9+/=.]{64}|[0-9]{19})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"salesforce", "5AEP861", "3MVG9"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SalesforceRefreshToken
}

func (s Scanner) Description() string {
	return "Salesforce is a customer relationship management (CRM) platform that provides a suite of applications and APIs. OAuth 2.0 refresh tokens are long-lived credentials that allow applications to obtain new access tokens without requiring user interaction. They enable continuous access to an organization's data and must be handled securely."
}

// FromData will find and optionally verify Salesforceoauth2 refresh token in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueTokenMatches, uniqueKeyMatches, uniqueSecretMatches := make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})
	for _, match := range refreshTokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokenMatches[match[1]] = struct{}{}
	}

	for _, match := range consumerKeyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeyMatches[match[1]] = struct{}{}
	}

	for _, match := range consumerSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecretMatches[match[1]] = struct{}{}
	}

	for refreshToken := range uniqueTokenMatches {
		for key := range uniqueKeyMatches {
			for secret := range uniqueSecretMatches {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_SalesforceRefreshToken,
					Raw:          []byte(refreshToken),
					RawV2:        fmt.Appendf([]byte{}, "%s:%s:%s", refreshToken, key, secret),
				}

				if verify {
					isVerified, verificationErr := s.verifyMatch(ctx, s.getClient(), refreshToken, key, secret)
					s1.Verified = isVerified
					if verificationErr != nil {
						s1.SetVerificationError(verificationErr, secret)
					}
				}

				results = append(results, s1)
			}
		}
	}

	return
}

// verifyMatch attempts to validate a Salesforce Refresh Token.
func (s Scanner) verifyMatch(ctx context.Context, client *http.Client, refreshToken, key, secret string) (bool, error) {
	form := url.Values{}
	form.Set("token", refreshToken)
	form.Set("client_id", key)
	form.Set("client_secret", secret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://login.salesforce.com/services/oauth2/introspect",
		strings.NewReader(form.Encode()))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to perform request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("failed to read error response body: %w", err)
		}
		var apiResp introspectAPIResponse
		if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
			return false, fmt.Errorf("failed to unmarshal error response: %w (body: %s)", err, string(bodyBytes))
		}

		if !apiResp.Active {
			return false, nil
		}
		return true, nil

	case http.StatusBadRequest:
		// Salesforce returns a 400 Bad Request if the consumer key/secret are valid, but the refresh token is invalid or missing
		return false, nil

	case http.StatusUnauthorized:
		// Salesforce returns a 401 Unauthorized if the consumer key/secret are invalid.
		// This means that a 401 can also occur when the refresh token is valid but the consumer key or secret is incorrect.
		return false, fmt.Errorf("unauthorized: invalid client credentials")

	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

type introspectAPIResponse struct {
	Active bool `json:"active"`
}
