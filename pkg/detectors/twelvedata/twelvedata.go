package twelvedata

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"twelvedata"}) + `\b([a-z0-9]{32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("twelvedata")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	var results []detectors.Result

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_TwelveData,
			Raw:          resMatch,
		}
		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.twelvedata.com/earliest_timestamp?symbol=AAPL&interval=1day&apikey="+string(resMatch), nil)
			if err != nil {
				continue
			}

			res, err := client.Do(req)

			if err != nil {
				continue
			}

			defer res.Body.Close()

			body, err := io.ReadAll(res.Body)
			if err != nil {
				continue
			}

			if !bytes.Contains(body, []byte("401")) {
				s1.Verified = true
			} else if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
				continue
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_TwelveData
}
