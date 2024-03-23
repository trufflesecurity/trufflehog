package quickbase

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
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
	keyPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"quickbase"}) + `\b([0-9a-z]{6}_[a-z0-9]{4}_[0-9]{1}_[a-zA-Z-0-9]{28})\b`)
	hostPat = regexp.MustCompile(detectors.PrefixRegex([]string{"quickbase"}) + `\b([a-zA-Z_]{4,28}.quickbase.com)\b`)
	idPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"quickbase", "id"}) + `\b([0-9a-z]{9})\b$`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"quickbase"}
}

// FromData will find and optionally verify Quickbase secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	hostMatches := hostPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, hostMatch := range hostMatches {
			if len(hostMatch) != 2 {
				continue
			}
			resHostMatch := strings.TrimSpace(hostMatch[1])

			for _, idMatch := range idMatches {
				if len(idMatch) != 2 {
					continue
				}
				idLen := len(idMatch)
				resIdMatch := strings.TrimSpace(idMatch[idLen-1])
				
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Quickbase,
					Raw:          []byte(resMatch),
				}

				if verify {
					req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.quickbase.com/v1/apps/%s", resIdMatch), nil)
					if err != nil {
						continue
					}
					req.Header.Add("QB-Realm-Hostname",resHostMatch)
					req.Header.Add("Authorization", fmt.Sprintf("QB-USER-TOKEN %s", resMatch))
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
		}

	}

	return detectors.CleanResults(results), nil
}
