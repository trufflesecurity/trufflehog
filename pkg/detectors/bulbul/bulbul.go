package bulbul

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bulbul"}) + `\b([a-z0-9]{32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("bulbul")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Bulbul,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://prod-api.bulbul.io/view_all_users?api_key="+string(resMatch), nil)
			if err != nil {
				continue
			}
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					responseBody, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}
					validResponse := bytes.Contains(responseBody, []byte(`"message":"Successful",`))
					if validResponse {
						s1.Verified = true
					} else {
						s1.Verified = false
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
	return detectorspb.DetectorType_Bulbul
}
