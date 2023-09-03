package commodities

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"commodities"}) + `\b([a-zA-Z0-9]{60})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("commodities")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Commodities,
			Raw:          resMatch,
		}

		if verify {
			client.Timeout = 5 * time.Second
			req, err := http.NewRequestWithContext(ctx, "GET", string(bytes.Split(resMatch, []byte("="))[0]), nil)
			if err != nil {
				continue
			}
			res, err := client.Do(req)
			if err == nil {
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}
				validResponse := bytes.Contains(bodyBytes, []byte(`"success":true`))
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
	return detectorspb.DetectorType_Commodities
}
