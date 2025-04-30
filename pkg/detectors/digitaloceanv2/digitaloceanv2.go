package digitaloceanv2

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
	keyPat = regexp.MustCompile(`\b((?:dop|doo|dor)_v1_[a-f0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"dop_v1_", "doo_v1_", "dor_v1_"}
}

// FromData will find and optionally verify DigitalOceanV2 secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueTokens = make(map[string]struct{})

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[matches[0]] = struct{}{}
	}

	for token := range uniqueTokens {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_DigitalOceanV2,
			Raw:          []byte(token),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			// Check if the token is a refresh token or an access token
			switch {
			case strings.HasPrefix(token, "dor_v1_"):
				verified, verificationErr, newAccessToken := verifyRefreshToken(ctx, client, token)
				s1.SetVerificationError(verificationErr)
				s1.Verified = verified
				if s1.Verified {
					s1.AnalysisInfo = map[string]string{
						"key": newAccessToken,
					}
				}
			case strings.HasPrefix(token, "doo_v1_"), strings.HasPrefix(token, "dop_v1_"):
				verified, verificationErr := verifyAccessToken(ctx, client, token)
				s1.Verified = verified
				s1.SetVerificationError(verificationErr)
				if s1.Verified {
					s1.AnalysisInfo = map[string]string{
						"key": token,
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

// verifyRefreshToken verifies the refresh token by making a request to the DigitalOcean API.
// If the token is valid, it returns the new access token and no error.
// If the token is invalid/expired, it returns an empty string and no error.
// If an error is encountered, it returns an empty string along and the error.
func verifyRefreshToken(ctx context.Context, client *http.Client, token string) (bool, error, string) {
	// Ref: https://docs.digitalocean.com/reference/api/oauth/

	url := "https://cloud.digitalocean.com/v1/oauth/token?grant_type=refresh_token&refresh_token=" + token
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err), ""
	}

	res, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to make request: %w", err), ""
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err), ""
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		var responseMap map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &responseMap); err != nil {
			return false, fmt.Errorf("failed to parse response body: %w", err), ""
		}
		// Extract the access token from the response
		accessToken, exists := responseMap["access_token"].(string)
		if !exists {
			return false, fmt.Errorf("access_token not found in response: %s", string(bodyBytes)), ""
		}
		return true, nil, accessToken
	case http.StatusUnauthorized:
		return false, nil, ""
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode), ""
	}
}

// verifyAccessToken verifies the access token by making a request to the DigitalOcean API.
// If the token is valid, it returns true and no error.
// If the token is invalid, it returns false and no error.
// If an error is encountered, it returns false along with the error.
func verifyAccessToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	// Ref: https://docs.digitalocean.com/reference/api/digitalocean/#tag/Account

	url := "https://api.digitalocean.com/v2/account"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to make request: %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DigitalOceanV2
}

func (s Scanner) Description() string {
	return "DigitalOcean is a cloud service provider offering scalable compute and storage solutions. DigitalOcean API keys can be used to access and manage these resources."
}
