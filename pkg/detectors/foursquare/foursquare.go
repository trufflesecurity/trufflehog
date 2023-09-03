package foursquare

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

	keyPat      = regexp.MustCompile(detectors.PrefixRegex([]string{"foursquare"}) + `\b([0-9A-Z]{48})\b`)
	secretMatch = regexp.MustCompile(detectors.PrefixRegex([]string{"foursquare"}) + `\b([0-9A-Z]{48})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("foursquare")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	secretMatches := secretMatch.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])
		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}
			resSecret := bytes.TrimSpace(secretMatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_FourSquare,
				Raw:          resMatch,
				RawV2:        append(resMatch, resSecret...),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.foursquare.com/v2/venues/trending?client_id=%s&client_secret=%s&v=20211019&near=LA", string(resMatch), string(resSecret)), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FourSquare
}
