package appointedd

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"appointedd"}) + `\b([a-zA-Z0-9=+]{88})`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("appointedd")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Appointedd,
			Raw:          resMatch,
		}
		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.appointedd.com/v1/availability/slots", nil)
			if err != nil {
				continue
			}
			req.Header.Add("X-API-KEY", string(resMatch))
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()

				if bodyBytes, err := io.ReadAll(res.Body); err == nil {
					if bytes.Contains(bodyBytes, []byte("total")) {
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

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Appointedd
}
