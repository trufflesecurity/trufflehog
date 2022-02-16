package pdflayer

import (
	"context"
	"fmt"
	"io/ioutil"

	// "log"
	"regexp"
	"strings"

	"net/http"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"pdflayer"}) + `\b([a-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"pdflayer"}
}

// FromData will find and optionally verify PdfLayer secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_PdfLayer,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.pdflayer.com/api/convert?access_key=%s&document_url=https://pdflayer.com/downloads/invoice.html", resMatch), nil)
			res, err := client.Do(req)
			if err == nil {
				bodyBytes, err := ioutil.ReadAll(res.Body)
				if err == nil {
					bodyString := string(bodyBytes)
					errCode := strings.Contains(bodyString, `"code":101`)
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						if errCode {
							s1.Verified = false
						} else {
							s1.Verified = true
						}
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
