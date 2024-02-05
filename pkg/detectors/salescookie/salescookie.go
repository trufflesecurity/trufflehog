package salescookie

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"salescookie"}) + `\b([a-zA-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"salescookie"}
}

// FromData will find and optionally verify Salescookie secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Salescookie,
			Raw:          []byte(resMatch),
		}

		if verify {
			payload := strings.NewReader(`{"date":"2021-07-04T02:47:42.1442597Z","uniqueId":"id-123","revenue":1.3,"profit":-2.5,"currency":"USD","transactionStatus":"closed won","customer":"Candy By Mail","product":"Lemon Cake","owner1":"John Doe","owner2":"Jane Doe","owner3":"Bob Smith","team1":"USA","team2":"Washington","team3":"98004","quantity":3,"costPerUnit":3.14,"taxes":6.54,"otherText1":"additional data","otherText2":"more data","otherText3":"even more data","otherNumeric1":123.45,"otherNumeric2":54.321,"otherNumeric3":-98.76,"otherDate1":"2019-01-03T06:03:01Z","otherDate2":"2019-05-10T08:05:09Z","otherDate3":"2019-09-04T12:17:33Z"}`)
			req, err := http.NewRequestWithContext(ctx, "POST", "https://salescookie.com/app/Api/CreateTransaction", payload)
			if err != nil {
				continue
			}
			req.Header.Add("X-ApiKey", resMatch)
			req.Header.Add("Content-Type", "application/json")
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
				} else {
					// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
					if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Salescookie
}
