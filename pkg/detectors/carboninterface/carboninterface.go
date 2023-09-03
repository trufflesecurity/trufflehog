package carboninterface

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"carboninterface"}) + `\b([a-zA-Z0-9]{21})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("carboninterface")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := match[1]

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_CarbonInterface,
			Raw:          resMatch,
		}

		if verify {
			payload := fmt.Sprintf(`{"type":"flight","passengers":2,"legs":[{"departure_airport":"sfo","destination_airport":"yyz"},{"departure_airport":"yyz","destination_airport":"sfo"}]}`)
			req, err := http.NewRequestWithContext(ctx, "POST", "https://www.carboninterface.com/api/v1/estimates", bytes.NewBufferString(payload))
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
			req.Header.Add("Content-type", "application/json")
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CarbonInterface
}
