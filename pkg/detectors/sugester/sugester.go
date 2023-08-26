package sugester

import (
	"bytes"
	"context"
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

	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"sugester"}) + `\b([a-zA-Z0-9]{32})\b`)
	domainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sugester"}) + `\b([a-zA-Z0-9_.!+$#^*%]{3,32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("sugester")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	domainMatches := domainPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, domainmatch := range domainMatches {
			if len(domainmatch) != 2 {
				continue
			}
			resDomainMatch := bytes.TrimSpace(domainmatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Sugester,
				Raw:          resMatch,
			}

			if verify {
				req, err := http.NewRequest("GET", "https://"+string(resDomainMatch)+".sugester.com/app/clients.json?api_token="+string(resMatch), nil)
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
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, false) {
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
