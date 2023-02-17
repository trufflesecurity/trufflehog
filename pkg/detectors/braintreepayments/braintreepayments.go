package braintreepayments

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundry characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"braintree"}) + `\b([0-9a-f]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"braintree"}) + `\b([0-9a-z]{16})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"braintree"}
}

// FromData will find and optionally verify BraintreePayments secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}

			resIdMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_BraintreePayments,
				Raw:          []byte(resMatch),
			}

			if verify {
				payload := strings.NewReader(`{"query": "query { ping }"}`)
				req, err := http.NewRequestWithContext(ctx, "POST", "https://payments.braintree-api.com/graphql", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("Braintree-Version", "2019-01-01")
				req.SetBasicAuth(resIdMatch, resMatch)
				res, err := client.Do(req)
				if err == nil {
					bodyBytes, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}

					bodyString := string(bodyBytes)
					validResponse := strings.Contains(bodyString, `"data":{`)

					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 && validResponse {
						s1.Verified = true
					} else {
						// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_BraintreePayments
}
