package elasticemail

import (
	"context"
	// "log"
	"regexp"
	"strings"

	// "fmt"
	"encoding/json"
	"io/ioutil"

	"net/http"

	"github.com/trufflesecurity/trufflehog/pkg/common"
	"github.com/trufflesecurity/trufflehog/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"elastic"}) + `\b([A-Za-z0-9_-]{96})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"elasticemail"}
}

// FromData will find and optionally verify ElasticEmail secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_ElasticEmail,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.elasticemail.com/v2/account/profileoverview?apikey="+resMatch, nil)
			res, err := client.Do(req)
			if err != nil {
				continue
			}
			defer res.Body.Close()
			var byteData []byte
			_, err = res.Body.Read(byteData)
			if err != nil {
				continue
			}

			defer res.Body.Close()
			data, err := ioutil.ReadAll(res.Body)
			if err != nil {
				continue
			}
			var ResVar struct {
				Success bool `json:"success"`
			}
			if err := json.Unmarshal(data, &ResVar); err != nil {
				continue
			}
			if ResVar.Success {
				s1.Verified = true
			} else {

				if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
					continue
				}
			}
		}

		results = append(results, s1)
	}
	return detectors.CleanResults(results), nil
}
func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}
