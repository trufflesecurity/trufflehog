package zulipchat

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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"zulipchat"}) + common.BuildRegex(common.AlphaNumPattern, "", 32))
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"zulipchat"}) + common.EmailPattern)
	domainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"zulipchat", "domain"}) + common.SubDomainPattern)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"zulipchat"}
}

// FromData will find and optionally verify ZulipChat secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
	domainMatches := domainPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			// getting the last word of the string
			resIdMatch := strings.TrimSpace(idMatch[0][strings.LastIndex(idMatch[0], " ")+1:])

			for _, domainMatch := range domainMatches {
				if len(domainMatch) != 2 {
					continue
				}

				resDomainMatch := strings.TrimSpace(domainMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ZulipChat,
					Raw:          []byte(resMatch),
				}

				if verify {
					req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s.zulipchat.com/api/v1/users", resDomainMatch), nil)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
					req.SetBasicAuth(resIdMatch, resMatch)
					res, err := client.Do(req)

					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else {
							// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
							if detectors.IsKnownFalsePositive(resIdMatch, detectors.DefaultFalsePositives, true) {
								continue
							}
						}
					}
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}
