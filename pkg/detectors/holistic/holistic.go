package holistic

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"holistic"}) + `\b([0-9a-f]{64})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("holistic")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Holistic,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.holistic.dev/api/v1/project", nil)
			if err != nil {
				continue
			}
			req.Header.Add("x-api-key", string(resMatch))
			res, err := client.Do(req)
			if err == nil {
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}

				errorResponse := bytes.Contains(bodyBytes, []byte(`"data":[]`))

				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 && !errorResponse {
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Holistic
}
