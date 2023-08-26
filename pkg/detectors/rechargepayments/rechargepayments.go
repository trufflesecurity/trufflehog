package rechargepayments

import (
	"bytes"
	"context"
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
	verifyURL = []byte("https://api.rechargeapps.com/token_information")

	tokenPats = map[string]*regexp.Regexp{
		"Newer API Keys":        regexp.MustCompile(`\bsk(_test)?_(1|2|3|5|10)x[123]_[0-9a-fA-F]{64}\b`),
		"Old API key (SHA-224)": regexp.MustCompile(`\b[0-9a-fA-F]{56}\b`),
		"Old API key (MD-5)":    regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`),
	}
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("sk_1x1"), []byte("sk_1x3"), []byte("sk_2x1"), []byte("sk_2x2"), []byte("sk_3x3"), []byte("sk_5x3"), []byte("sk_10x3"), []byte("sk_test_1x1"), []byte("sk_test_1x3"), []byte("sk_test_2x1"), []byte("sk_test_2x2"), []byte("sk_test_3x3"), []byte("sk_test_5x3"), []byte("sk_test_10x3"), []byte("X-Recharge-Access-Token")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	for _, tokenPat := range tokenPats {
		tokens := tokenPat.FindAll(data, -1)

		for _, token := range tokens {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_RechargePayments,
				Raw:          bytes.TrimSpace(token),
			}
			if verify {
				client := common.SaneHttpClient()
				req, err := http.NewRequestWithContext(ctx, "GET", string(verifyURL), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("X-Recharge-Access-Token", string(token))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()

					if res.StatusCode == http.StatusOK {
						s1.Verified = true
					}
				}
			}

			if !s1.Verified && detectors.IsKnownFalsePositive(s1.Raw, detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_RechargePayments
}
