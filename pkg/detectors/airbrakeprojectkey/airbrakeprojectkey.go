package airbrakeprojectkey

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"airbrake"}) + `\b([a-zA-Z-0-9]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"airbrake"}) + `\b([0-9]{6})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"airbrake"}
}

// FromData will find and optionally verify AirbrakeProjectKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}

			resIdMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AirbrakeProjectKey,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resIdMatch),
			}
			s1.ExtraData = map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/airbrake/",
			}

			if verify {
				payload := strings.NewReader(`{"environment":"production","username":"john","email":"john@smith.com","repository":"https://github.com/airbrake/airbrake","revision":"38748467ea579e7ae64f7815452307c9d05e05c5","version":"v2.0"}`)

				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.airbrake.io/api/v4/projects/"+resIdMatch+"/deploys?key="+resMatch, payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					}
				}
			}

			if !s1.Verified {
				if detectors.IsKnownFalsePositive(string(s1.Raw), detectors.DefaultFalsePositives, true) {
					continue
				}
			}

			results = append(results, s1)

		}

	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AirbrakeProjectKey
}
