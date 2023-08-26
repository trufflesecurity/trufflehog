package sheety

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sheety"}) + `\b([0-9a-z]{64})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"sheety"}) + `\b([0-9a-z]{32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("sheety")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	idmatches := idPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])
		for _, idmatch := range idmatches {
			if len(idmatch) != 2 {
				continue
			}
			resIdMatch := bytes.TrimSpace(idmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Sheety,
				Raw:          resMatch,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.sheety.co/"+string(resIdMatch)+"/restaurantMenu/menuItems", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
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
	return detectorspb.DetectorType_Sheety
}
