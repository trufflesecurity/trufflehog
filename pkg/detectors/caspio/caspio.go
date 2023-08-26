package caspio

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"

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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"caspio"}) + `\b([a-z0-9]{50})\b`)
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"caspio"}) + `\b([a-z0-9]{50})\b`)
	domainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"caspio"}) + `\b([a-z0-9]{8})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("caspio")}
}

// FromData will find and optionally verify Caspio secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)
	domainMatches := domainPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}

			resIdMatch := bytes.TrimSpace(idMatch[1])

			for _, domainMatch := range domainMatches {
				if len(domainMatch) != 2 {
					continue
				}

				resDomainMatch := bytes.TrimSpace(domainMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Caspio,
					Raw:          resMatch,
					RawV2:        append(append(resMatch, resIdMatch...), resDomainMatch...),
				}

				if verify {
					payload := bytes.NewBuffer([]byte(fmt.Sprintf(`grant_type=client_credentials&client_id=%s&client_secret=%s`, string(resIdMatch), string(resMatch))))
					req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("https://%s.caspio.com/oauth/token", string(resDomainMatch)), payload)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "text/plain")
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Caspio
}
