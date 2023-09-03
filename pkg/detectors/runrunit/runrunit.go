package runrunit

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

	keyPat       = regexp.MustCompile(detectors.PrefixRegex([]string{"runrunit"}) + `\b([0-9a-f]{32})\b`)
	userTokenPat = regexp.MustCompile(detectors.PrefixRegex([]string{"runrunit"}) + `\b([0-9A-Za-z]{18,20})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("runrunit")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	userTokenMatches := userTokenPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		resMatch := bytes.TrimSpace(match[1])

		for _, userTokenMatch := range userTokenMatches {
			if len(userTokenMatch) != 2 {
				continue
			}

			resUserTokenMatch := bytes.TrimSpace(userTokenMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_RunRunIt,
				Raw:          resMatch,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://runrun.it/api/v1.0/users", nil)
				if err != nil {
					continue
				}

				req.Header.Add("App-Key", string(resMatch))
				req.Header.Add("User-Token", string(resUserTokenMatch))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()

					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) || detectors.IsKnownFalsePositive(resUserTokenMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_RunRunIt
}
