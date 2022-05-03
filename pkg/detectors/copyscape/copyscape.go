package copyscape

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"io/ioutil"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"copyscape"}) + `\b([0-9a-z]{16})\b`)
	idPat = regexp.MustCompile(detectors.PrefixRegex([]string{"copyscapeId"}) + `\b([0-9a-zA-Z._-]{4,22})\b`)

)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"copyscape"}
}

// FromData will find and optionally verify Copyscape secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	idmatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])
		for _, idmatch := range idmatches {
			if len(match) != 2 {
				continue
			}
			resIdMatch := strings.TrimSpace(idmatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Copyscape,
				Raw:          []byte(resMatch),
			}

			if verify {
				url := fmt.Sprintf("http://www.copyscape.com/api/?u=%s&k=%s&o=csearch&x=1",resIdMatch,resMatch)
				req, err := http.NewRequestWithContext(ctx, "GET",url , nil)
				if err != nil {
					continue
				}
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					bodyBytes, _ := ioutil.ReadAll(res.Body)
					// if err != nil {
					// 	continue
					// }
					body := string(bodyBytes)
					//Used error as base for the fail safe, due to late response on success token
					if !strings.Contains(body, "error") {
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
		
	}

	return detectors.CleanResults(results), nil
}
