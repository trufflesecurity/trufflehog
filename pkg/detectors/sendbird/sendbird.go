package sendbird

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

	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"sendbird"}) + `\b([0-9a-f]{40})\b`)
	appIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sendbird"}) + `\b([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("sendbird")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	appIdMatches := appIdPat.FindAllSubmatch(data, -1)

	for _, appIdMatch := range appIdMatches {
		if len(appIdMatch) != 2 {
			continue
		}
		resAppIdMatch := bytes.TrimSpace(appIdMatch[1])

		for _, match := range matches {
			if len(match) != 2 {
				continue
			}
			resMatch := bytes.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Sendbird,
				Raw:          resMatch,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api-%s.sendbird.com/v3/users", string(resAppIdMatch)), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Api-Token", string(resMatch))
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
	return detectorspb.DetectorType_Sendbird
}
