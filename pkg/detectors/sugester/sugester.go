package sugester

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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"sugester"}) + `\b([a-zA-Z0-9]{32})\b`)
	domainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sugester"}) + `\b([a-zA-Z0-9_.!+$#^*%]{3,32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sugester"}
}

// FromData will find and optionally verify Sugester secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	domainMatches := domainPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, domainmatch := range domainMatches {
			if len(match) != 2 {
				continue
			}
			resDomainMatch := strings.TrimSpace(domainmatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Sugester,
				Raw:          []byte(resMatch),
			}

			if verify {
				req, err := http.NewRequest("GET", "https://"+resDomainMatch+".sugester.com/app/clients.json?api_token="+resMatch, nil)
				if err != nil {
					continue
				}
				req.Header.Add("Accept", "application/vnd.sugester+json; version=3")
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Sugester
}
