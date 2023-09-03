package mattermostpersonaltoken

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

	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"mattermost"}) + `\b([a-z0-9]{26})\b`)
	serverPat = regexp.MustCompile(detectors.PrefixRegex([]string{"mattermost"}) + `\b([A-Za-z0-9-_]{1,}.cloud.mattermost.com)\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("mattermost")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)
	serverMatches := serverPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, serverMatch := range serverMatches {
			if len(serverMatch) != 2 {
				continue
			}
			serverRes := bytes.TrimSpace(serverMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_MattermostPersonalToken,
				Raw:          resMatch,
				RawV2:        append(resMatch, serverRes...),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/api/v4/users/stats", serverRes), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MattermostPersonalToken
}
