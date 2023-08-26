package teamgate

import (
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
	client   = common.SaneHttpClient()
	tokenPat = regexp.MustCompile(detectors.PrefixRegex([]string{"teamgate"}) + `\b([a-z0-9]{40})\b`)
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"teamgate"}) + `\b([a-zA-Z0-9]{80})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("teamgate")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := tokenPat.FindAllSubmatch(data, -1)
	keyMatches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := match[1]

		for _, keyMatch := range keyMatches {
			if len(keyMatch) != 2 {
				continue
			}

			resKeyMatch := keyMatch[1]

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Teamgate,
				Raw:          resMatch,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.teamgate.com/v4/users", nil)
				if err != nil {
					continue
				}

				req.Header.Add("X-Auth-Token", string(resMatch))
				req.Header.Add("X-App-Key", string(resKeyMatch))

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
	return detectorspb.DetectorType_Teamgate
}
