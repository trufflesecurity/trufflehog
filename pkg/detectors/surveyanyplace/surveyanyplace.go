package surveyanyplace

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"survey"}) + `\b([a-z0-9A-Z]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"survey"}) + `\b([a-z0-9A-Z-]{36})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"surveyanyplace"}
}

// FromData will find and optionally verify SurveyAnyplace secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idmatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, idmatch := range idmatches {
			resIdMatch := strings.TrimSpace(idmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_SurveyAnyplace,
				Raw:          []byte(resMatch),
			}

			if verify {
				payload := strings.NewReader(`{
					"codes": [
					"code1",
					"code2"
					]
					}`)
				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.surveyanyplace.com/v1/surveys/"+resIdMatch+"/accesscodes", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("API %s", resMatch))
				req.Header.Add("Content-Type", "application/json")
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
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

func (s Scanner) Description() string {
	return "SurveyAnyplace is a platform for creating surveys and quizzes. The detected credential can be used to access and manage surveys on this platform."
}
