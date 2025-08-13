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
			isVerifiedProd, verificationErrProd := verifyYousignProdURL(ctx, client, resMatch)
			s1.Verified = isVerifiedProd
			if verificationErrProd != nil {
				s1.SetVerificationError(verificationErrProd, resMatch)
			} else {
				isVerifiedStaging, verificationErrStaging := verifyYousignStagingURL(ctx, client, resMatch)
				s1.Verified = isVerifiedStaging
				s1.SetVerificationError(verificationErrStaging, resMatch)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_YouSign
}

func (s Scanner) Description() string {
	return "Yousign is an electronic signature service used to sign and manage documents online. Yousign API keys can be used to access and manage these documents."
}

func verifyYousignProdURL(ctx context.Context, client *http.Client, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/users", PROD_URL), nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))

	return verifyStatusCode(req, client)
}

func verifyYousignStagingURL(ctx context.Context, client *http.Client, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/users", STAGING_URL), nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))

	return verifyStatusCode(req, client)
}

func verifyStatusCode(req *http.Request, client *http.Client) (bool, error) {
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
