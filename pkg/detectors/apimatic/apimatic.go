package apimatic

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	apiKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"apimatic", "apikey"}) + `\b([a-zA-Z0-9_-]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"apimatic"}
}

// FromData will find and optionally verify APIMatic secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueApiKeys := make(map[string]struct{})
	for _, matches := range apiKeyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueApiKeys[matches[1]] = struct{}{}
	}

	for apiKey := range uniqueApiKeys {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_APIMatic,
			Raw:          []byte(apiKey),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyAPImaticKey(ctx, client, apiKey)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)

	}
	return results, nil
}

func verifyAPImaticKey(ctx context.Context, client *http.Client, key string) (bool, error) {
	timeout := 10 * time.Second
	client.Timeout = timeout

	// api docs: https://docs.apimatic.io/platform-api/#/http/api-endpoints/code-generation-external-apis/list-all-code-generations
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.apimatic.io/code-generations", http.NoBody)
	if err != nil {
		return false, err
	}

	// authentication documentation: https://docs.apimatic.io/platform-api/#/http/guides/authentication
	req.Header.Set("Authorization", "X-Auth-Key "+key)
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
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_APIMatic
}

func (s Scanner) Description() string {
	return "APIMatic provides tools for generating SDKs, API documentation, and code snippets. APIMatic credentials can be used to access and manage these tools and services."
}
