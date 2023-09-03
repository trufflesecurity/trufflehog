package auth0managementapitoken

import (
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

	managementApiTokenPat = regexp.MustCompile(detectors.PrefixRegex([]string{"auth0"}) + `\b(ey[a-zA-Z0-9._-]+)\b`)
	domainPat             = regexp.MustCompile(`([a-zA-Z0-9\-]{2,16}\.[a-zA-Z0-9_-]{2,3}\.auth0\.com)`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("auth0")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	managementApiTokenMatches := managementApiTokenPat.FindAllSubmatch(data, -1)
	domainMatches := domainPat.FindAllSubmatch(data, -1)

	for _, managementApiTokenMatch := range managementApiTokenMatches {
		if len(managementApiTokenMatch) != 2 {
			continue
		}
		managementApiTokenRes := managementApiTokenMatch[1]
		if len(managementApiTokenRes) < 2000 || len(managementApiTokenRes) > 5000 {
			continue
		}

		for _, domainMatch := range domainMatches {
			if len(domainMatch) != 2 {
				continue
			}

			domainRes := domainMatch[1]

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Auth0ManagementApiToken,
				Redacted:     string(domainRes),
				Raw:          managementApiTokenRes,
				RawV2:        append(managementApiTokenRes, domainRes...),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://"+string(domainRes)+"/api/v2/users", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(managementApiTokenRes)))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(managementApiTokenRes, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Auth0ManagementApiToken
}
