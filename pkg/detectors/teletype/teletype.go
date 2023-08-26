package teletype

import (
	"bytes"
	"context"
	"io"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"teletype"}) + `\b([0-9a-zA-Z-]{64})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("teletype")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Teletype,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.teletype.app/public/api/v1/messages", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("X-Auth-Token", string(resMatch))
			res, err := client.Do(req)
			if err == nil {
				bodyBytes, err := io.ReadAll(res.Body)
				defer res.Body.Close()
				if err != nil {
					continue
				}

				validResponse := bytes.Contains(bodyBytes, []byte(`"code":401`))

				if res.StatusCode >= 200 && res.StatusCode < 300 {
					if validResponse {
						s1.Verified = false
					} else {
						s1.Verified = true
					}
				} else {
					if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Teletype
}
