package surveyanyplace

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"survey"}) + `\b([a-z0-9A-Z]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"survey"}) + `\b([a-z0-9A-Z-]{36})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("surveyanyplace")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	keyMatches := keyPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)

	for _, match := range keyMatches {

		if len(match) != 2 {
			continue
		}

		resMatch := bytes.TrimSpace(match[1])

		for _, idmatch := range idMatches {

			if len(idmatch) != 2 {
				continue
			}

			resIdmatch := bytes.TrimSpace(idmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_SurveyAnyplace,
				Raw:          resMatch,
			}

			if verify {

				payload := bytes.NewReader([]byte(`{
					"codes": [
					"code1",
					"code2"
					]
					}`))

				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.surveyanyplace.com/v1/surveys/"+string(resIdmatch)+"/accesscodes", payload)

				if err != nil {
					continue
				}

				req.Header.Add("Authorization", fmt.Sprintf("API %s", string(resMatch)))
				req.Header.Add("Content-Type", "application/json")

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
	return detectorspb.DetectorType_SurveyAnyplace
}
