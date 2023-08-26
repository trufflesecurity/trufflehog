package zulipchat

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

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"zulipchat"}) + common.BuildRegex(common.AlphaNumPattern, "", 32))
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"zulipchat"}) + common.EmailPattern)
	domainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"zulipchat", "domain"}) + common.SubDomainPattern)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("zulipchat")}
}

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

			resIdMatch := bytes.TrimSpace(idMatch[0][bytes.LastIndex(idMatch[0], []byte(" "))+1:])

			for _, domainMatch := range domainMatches {
				if len(domainMatch) != 2 {
					continue
				}

				resDomainMatch := bytes.TrimSpace(domainMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ZulipChat,
					Raw:          resMatch,
				}

				if verify {
					req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s.zulipchat.com/api/v1/users", string(resDomainMatch)), nil)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
					req.SetBasicAuth(string(resIdMatch), string(resMatch))
					res, err := client.Do(req)

					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else {
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

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ZulipChat
}
