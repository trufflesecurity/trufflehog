package maxmindlicense

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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"maxmind", "geoip"}) + `\b([0-9]{2,7})\b`)
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"maxmind", "geoip"}) + `\b([0-9A-Za-z]{16})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("maxmind"), []byte("geoip")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	keyMatches := keyPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)

	for _, keyMatch := range keyMatches {
		keyRes := bytes.TrimSpace(keyMatch[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}
			idRes := bytes.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_MaxMindLicense,
				Redacted:     string(idRes),
				Raw:          keyRes,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://geoip.maxmind.com/geoip/v2.1/country/8.8.8.8", nil)
				if err != nil {
					continue
				}
				req.SetBasicAuth(string(idRes), string(keyRes))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(keyRes, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_MaxMindLicense
}
