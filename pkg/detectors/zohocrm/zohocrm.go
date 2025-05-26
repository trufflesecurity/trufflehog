package zohocrm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

type UnauthorizedResponseBody struct {
	Code string `json:"code"`
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(1000\.[a-f0-9]{32}\.[a-f0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"1000."}
}

// FromData will find and optionally verify Zoho CRM secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	uniqueMatches := make(map[string]struct{})

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_ZohoCRM,
			Raw:          []byte(match),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyMatch(ctx, client, match)
			result.Verified = isVerified
			result.SetVerificationError(verificationErr, match)
		}

		results = append(results, result)
	}

	return
}

// Verifies the Zoho CRM API access token by making a GET request to the Zoho CRM API.
func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	endpoint := "https://www.zohoapis.com/crm/v7/Leads?fields=Email&per_page=1"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Zoho-oauthtoken %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, fmt.Errorf("failed to read response body: %v", err)
		}

		var responseBody UnauthorizedResponseBody
		err = json.Unmarshal(bodyBytes, &responseBody)
		if err != nil {
			return false, fmt.Errorf("failed to parse JSON response: %v", err)
		}

		switch responseBody.Code {
		case "OAUTH_SCOPE_MISMATCH":
			return true, nil
		case "INVALID_TOKEN":
			return false, nil
		default:
			return false, fmt.Errorf("unexpected error code: %s", responseBody.Code)
		}
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ZohoCRM
}

func (s Scanner) Description() string {
	return "Zoho CRM is a platform for managing sales, marketing, and customer support. Zoho CRM API access tokens allow access to these services through their REST API."
}
