package rechargepayments

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	verifyURL = "https://api.rechargeapps.com/token_information"

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	tokenPats = map[string]*regexp.Regexp{
		"Newer API Keys":        regexp.MustCompile(`\bsk(_test)?_(1|2|3|5|10)x[123]_[0-9a-fA-F]{64}\b`),
		"Old API key (SHA-224)": regexp.MustCompile(`\b[0-9a-fA-F]{56}\b`),
		"Old API key (MD-5)":    regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`),
	}
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sk_1x1", "sk_1x3", "sk_2x1", "sk_2x2", "sk_3x3", "sk_5x3", "sk_10x3", "sk_test_1x1", "sk_test_1x3", "sk_test_2x1", "sk_test_2x2", "sk_test_3x3", "sk_test_5x3", "sk_test_10x3", "X-Recharge-Access-Token"}
}

// FromData will find and optionally verify Recharge Payment secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	for _, tokenPat := range tokenPats {
		tokens := tokenPat.FindAllString(dataStr, -1)

		for _, token := range tokens {
			s := detectors.Result{
				DetectorType: detectorspb.DetectorType_RechargePayments,
				Raw:          []byte(token),
			}
			if verify {
				client := common.SaneHttpClient()
				req, err := http.NewRequestWithContext(ctx, "GET", verifyURL, nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("X-Recharge-Access-Token", token)
				res, err := client.Do(req)
				if err == nil {
					res.Body.Close() // The request body is unused.

					if res.StatusCode == http.StatusOK {
						s.Verified = true
					}
				}
			}

			if !s.Verified && detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_RechargePayments
}
