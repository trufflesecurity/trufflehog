package text2data

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"text2data"}) + `\b([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("text2data")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Text2Data,
			Raw:          resMatch,
		}

		if verify {
			data := url.Values{}
			data.Add("DocumentText", "Excellent location, opposite a very large mall with wide variety of shops, restaurants and more.")
			data.Add("PrivateKey", string(resMatch))

			req, err := http.NewRequestWithContext(ctx, "POST", "http://api.text2data.com/v3/Analyze", strings.NewReader(data.Encode()))
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/json")
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				body, errBody := io.ReadAll(res.Body)

				if errBody == nil {
					validResponse := bytes.Contains(body, []byte(`"DocSentimentResultString":"positive"`))

					if res.StatusCode >= 200 && res.StatusCode < 300 && validResponse {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

type Response struct {
	Status       int    `json:"Status"`
	ErrorMessage string `json:"ErrorMessage"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Text2Data
}
