package text2data

import (
	"context"
	"encoding/json"
	"io/ioutil"

	// "log"
	"regexp"
	"strings"

	"net/http"
	"net/url"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"text2data"}) + `\b([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"text2data"}
}

// FromData will find and optionally verify Text2Data secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Text2Data,
			Raw:          []byte(resMatch),
		}

		if verify {

			data := url.Values{}
			data.Add("DocumentText", "Excellent location, opposite a very large mall with wide variety of shops, restaurants and more.")
			data.Add("PrivateKey", resMatch)

			req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.text2data.com/v3/analyze", strings.NewReader(data.Encode()))
			req.Header.Add("Accept", "application/json")
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				body, errBody := ioutil.ReadAll(res.Body)

				if errBody == nil {

					var response Response
					json.Unmarshal(body, &response)

					if res.StatusCode >= 200 && res.StatusCode < 300 && response.Status == 1 && response.ErrorMessage == "" {
						s1.Verified = true
					} else {
						//This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}

			}
		}

		results = append(results, s1)
	}

	return detectors.CleanResults(results), nil
}

type Response struct {
	Status       int    `json:"Status"`
	ErrorMessage string `json:"ErrorMessage"`
}
