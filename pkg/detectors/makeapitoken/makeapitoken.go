package makeapitoken

import (
	"context"
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
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"make"}) + `\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`)
	// Pattern to match Make.com URLs in the data
	urlPat = regexp.MustCompile(`\b(eu|us)[12]\.make\.(com|celonis\.com)`)
)

func (Scanner) CloudEndpoint() string { return "" }

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"make.com", "make.celonis.com"}
}

// FromData will find and optionally verify Make secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	// Extract Make URLs from the data
	foundURLs := urlPat.FindAllString(dataStr, -1)

	// Get endpoints using EndpointCustomizer and deduplicate them
	uniqueURLs := make(map[string]struct{})
	for _, endpoint := range s.Endpoints(foundURLs...) {
		uniqueURLs[endpoint] = struct{}{}
	}

	// Skip creating results if no endpoints are available
	if len(uniqueURLs) == 0 {
		return
	}

	for match := range uniqueMatches {
		// Create results for each endpoint
		for endpoint := range uniqueURLs {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_MakeApiToken,
				Raw:          []byte(match),
				RawV2:        []byte(match + ":" + endpoint),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyMatch(ctx, client, match, endpoint)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, match)
			}

			results = append(results, s1)
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string, endpoint string) (bool, error) {
	// This endpoint returns 200 OK if the token is valid and the correct FQDN for the API is used.
	// https://developers.make.com/api-documentation/api-reference/users-greater-than-me#get-users-me-current-authorization
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/api/v2/users/me/current-authorization", endpoint), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Token "+token)

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
		// Determinate failure - invalid token
		return false, nil
	default:
		// Indeterminate failure - unexpected response
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MakeApiToken
}

func (s Scanner) Description() string {
	return "Make.com is a low-code/no-code automation platform that allows users to connect apps and services typically to automate business workflows. This detector identifies API tokens used for Make.com integrations."
}
