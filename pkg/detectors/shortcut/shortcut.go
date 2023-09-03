package shortcut

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"shortcut"}) + `\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("shortcut")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Shortcut,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.app.shortcut.com/api/v3/member", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("Shortcut-Token", string(resMatch))
			res, err := client.Do(req)

			if err != nil {
				return nil, err
			}

			defer res.Body.Close()

			verifiedBodyResponse, err := common.ResponseContainsSubstring(res.Body, "name")

			if err != nil {
				return nil, err
			}

			if res.StatusCode >= 200 && res.StatusCode < 300 && verifiedBodyResponse {
				s1.Verified = true
			} else {
				if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
					continue
				}
			}
		}
		results = append(results, s1)
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Shortcut
}
