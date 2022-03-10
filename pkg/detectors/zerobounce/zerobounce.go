package zerobounce

import (
	"context"
	"io/ioutil"
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

	//Make sure that your group is surrounded in boundry characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"zerobounce"}) + `\b([a-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"zerobounce"}
}

// FromData will find and optionally verify Zerobounce secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Zerobounce,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.zerobounce.net/v2/getcredits?api_key="+resMatch, nil)

			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				bodyBytes, _ := ioutil.ReadAll(res.Body)
				body := string(bodyBytes)

				if !strings.Contains(body, "-1") {
					s1.Verified = true
				} else {
					if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}

		}

		results = append(results, s1)
	}

	return detectors.CleanResults(results), nil
}
