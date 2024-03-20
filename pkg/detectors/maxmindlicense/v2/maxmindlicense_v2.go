package maxmindlicense

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
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

	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"maxmind", "geoip"}) + `\b([0-9]{2,7})\b`)
	keyPat = regexp.MustCompile(`\b([0-9A-Za-z]{6}_[0-9A-Za-z]{29}_mmk)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"maxmind", "geoip"}
}

func (Scanner) Version() int { return 2 }

// FromData will find and optionally verify MaxMindLicense secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, keyMatch := range keyMatches {
		keyRes := strings.TrimSpace(keyMatch[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}
			idRes := strings.TrimSpace(idMatch[1])

			s := detectors.Result{
				DetectorType: detectorspb.DetectorType_MaxMindLicense,
				Redacted:     idRes,
				Raw:          []byte(keyRes),
				RawV2:        []byte(keyRes + idRes),
				ExtraData: map[string]string{
					"rotation_guide": "https://howtorotate.com/docs/tutorials/maxmind/",
					"version":        fmt.Sprintf("%d", s.Version()),
				},
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://geoip.maxmind.com/geoip/v2.1/country/8.8.8.8", nil)
				if err != nil {
					continue
				}
				req.SetBasicAuth(idRes, keyRes)
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(keyRes, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}

			results = append(results, s)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MaxMindLicense
}
