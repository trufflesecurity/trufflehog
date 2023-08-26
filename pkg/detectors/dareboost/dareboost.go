package dareboost

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"dareboost"}) + `\b([0-9a-zA-Z]{60})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("dareboost")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Dareboost,
			Raw:          resMatch,
		}

		if verify {
			payload := bytes.NewBuffer([]byte(`{    "token": "` + string(resMatch) + `",    "location": "Paris"}`))

			req, err := http.NewRequestWithContext(ctx, "POST", "https://api.dareboost.com/0.8/config", payload)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			res, err := client.Do(req)
			if err == nil {
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}

				validResponse := bytes.Contains(bodyBytes, []byte(`"status":200`))

				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
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
	return detectorspb.DetectorType_Dareboost
}
