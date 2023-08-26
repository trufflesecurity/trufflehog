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

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat    = regexp.MustCompile(`(?i)\brzp_live_\w{10,20}\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"razor|secret|rzp|key"}) + `([A-Za-z0-9]{20,50})`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("rzp_")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	keyMatches := keyPat.FindAll(data, -1)

	for _, key := range keyMatches {
		secMatches := secretPat.FindAll(data, -1)

		for _, secret := range secMatches {

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_RazorPay,
				Raw:          key,
				RawV2:        append(key, secret...),
				Redacted:     string(key),
			}

			if verify {
				req, err := http.NewRequest("GET", "https://api.razorpay.com/v1/items?count=1", nil)
				if err != nil {
					continue
				}
				req.SetBasicAuth(string(key), string(secret))
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
						}
					}
				}
			}

			if !s1.Verified && detectors.IsKnownFalsePositive(key, detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s1)
		}

	}

	return detectors.CleanResults(results), nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_RazorPay
}
