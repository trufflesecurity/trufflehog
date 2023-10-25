package databrickstoken

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(`\b(dapi[0-9a-f]{32})(-\d)?\b`)
	domainPat = regexp.MustCompile(`\b([\w-\.]+\.(cloud\.databricks\.com|gcp\.databricks\.com|azuredatabricks\.net))\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"dapi"}
}

// FromData will find and optionally verify DatabricksToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	dataStr := string(data)

	matches := keyPat.FindAllString(dataStr, -1)
	domainMatches := domainPat.FindAllString(dataStr, -1)

	for _, match := range matches {

		for _, domain := range domainMatches {

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_DatabricksToken,
				Raw:          []byte(match),
				Verified:     false,
			}

			if verify {

				verifyUrl := fmt.Sprintf("https://%s/api/2.0/token/list", domain)

				req, err := http.NewRequestWithContext(ctx, "GET", verifyUrl, nil)
				if err != nil {
					continue
				}

				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", match))

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()

					if res.StatusCode == 200 {
						s1.Verified = true
						s1.ExtraData = map[string]string{"url": domain} // store the domain with the result
					} else {
						// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
						if detectors.IsKnownFalsePositive(match, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}

			results = append(results, s1)

		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DatabricksToken
}
