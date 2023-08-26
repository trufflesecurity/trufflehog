package nutritionix

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"nutritionix"}) + `\b([a-z0-9]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"nutritionix"}) + `\b([a-z0-9]{8})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("nutritionix")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}

			resIdMatch := bytes.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Nutritionix,
				Raw:          resMatch,
			}

			if verify {
				payload := bytes.NewBuffer([]byte(`{"query":"for breakfast i ate 2 eggs, bacon, and french toast","timezone":"US/Eastern"}`))
				req, err := http.NewRequestWithContext(ctx, "POST", "https://trackapi.nutritionix.com/v2/natural/nutrients", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("x-app-id", string(resIdMatch))
				req.Header.Add("x-app-key", string(resMatch))
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
	return detectorspb.DetectorType_Nutritionix
}
