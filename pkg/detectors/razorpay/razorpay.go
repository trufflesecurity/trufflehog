package razorpay

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

// The (`) character adds secondary encoding to parsed strings by Golang which also allows for escape sequences
var (
	client = common.SaneHttpClient()

	keyPat    = regexp.MustCompile(`(?i)\brzp_live_\w{10,20}\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"razor|secret|rzp|key"}) + `([A-Za-z0-9]{20,50})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"rzp_"}
}

// FromData will find and optionally verify RazorPay secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllString(dataStr, -1)

	for _, key := range keyMatches {

		if verify {
			secMatches := secretPat.FindAllString(dataStr, -1)

			for _, secret := range secMatches {

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_RazorPay,
					Raw:          []byte(key),
					RawV2:        []byte(key + secret),
					Redacted:     key,
				}

				req, err := http.NewRequest("GET", "https://api.razorpay.com/v1/items?count=1", nil)
				if err != nil {
					continue
				}
				req.SetBasicAuth(key, secret)
				res, err := client.Do(req)
				if err == nil {
					bodyBytes, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						if json.Valid(bodyBytes) {
							s1.Verified = true
						} else {
							s1.Verified = false
						}
					} else {
						// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
						if detectors.IsKnownFalsePositive(key, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}

				results = append(results, s1)
			}
		}

	}

	results = detectors.CleanResults(results)
	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_RazorPay
}
