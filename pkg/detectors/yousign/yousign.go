package yousign

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// docs: https://dev.yousign.com/#api-v3-documentation-new
const PROD_URL = "https://api.yousign.com"
const STAGING_URL = "https://staging-api.yousign.com"

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"yousign"}) + `\b([0-9a-z]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"yousign"}
}

// FromData will find and optionally verify Yousign secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_YouSign,
			Raw:          []byte(resMatch),
		}

		if verify {
			isVerified, err := verifyMatch(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(err, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	// Try V2 API (legacy) as fallback
	isVerified, err := tryEndpoint(ctx, client, token, PROD_URL, "/users")
	if isVerified || (err != nil && !isAuthError(err)) {
		return isVerified, err
	}

	// Try V2 Staging as final fallback
	return tryEndpoint(ctx, client, token, STAGING_URL, "/users")
}

func tryEndpoint(ctx context.Context, client *http.Client, token, baseURL, endpoint string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+endpoint, http.NoBody)
	if err != nil {
		return false, err
	}

	// YouSign API uses Bearer authentication
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	// V3 API expects JSON content type
	if strings.Contains(baseURL, "v3") {
		req.Header.Add("Content-Type", "application/json")
	}

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
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

// Helper function to determine if an error is authentication-related
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "invalid token") || strings.Contains(errStr, "401")
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_YouSign
}

func (s Scanner) Description() string {
	return "Yousign is an electronic signature service used to sign and manage documents online. Yousign API keys can be used to access and manage these documents."
}
