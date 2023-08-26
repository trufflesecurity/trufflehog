package planviewleankit

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

	keyPat       = regexp.MustCompile(detectors.PrefixRegex([]string{"planviewleankit", "planview"}) + `\b([0-9a-f]{128})\b`)
	subDomainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"planviewleankit", "planview"}) + `(?:subdomain).\b([a-zA-Z][a-zA-Z0-9.-]{1,23}[a-zA-Z0-9])\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("planviewleankit"), []byte("planview")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	subdomainMatches := subDomainPat.FindAllSubmatch(data, -1)

	for _, subdomainMatch := range subdomainMatches {
		if len(subdomainMatch) != 2 {
			continue
		}
		resSubdomainMatch := bytes.TrimSpace(subdomainMatch[1])

		for _, match := range matches {
			if len(match) != 2 {
				continue
			}
			resMatch := bytes.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_PlanviewLeanKit,
				Raw:          resMatch,
			}

			if verify {
				req, err := http.NewRequest("GET", fmt.Sprintf("https://%s.leankit.com/io/account", string(resSubdomainMatch)), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(resMatch)))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive([]byte(resMatch), detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_PlanviewLeanKit
}
