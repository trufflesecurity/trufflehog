package flightlabs

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"flightlabs"}) + `\b(ey[a-zA-Z0-9]{34}.ey[a-zA-Z0-9._-]{300,350})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("flightlabs")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_FlightLabs,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://app.goflightlabs.com/airports?access_key=%s", resMatch), nil)
			if err != nil {
				continue
			}

			res, err := client.Do(req)
			if err != nil || res.StatusCode < 200 || res.StatusCode >= 300 {
				if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
					continue
				}
			} else {
				s1.Verified = bytes.Contains(resMatch, []byte(`"id"`))
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FlightLabs
}
