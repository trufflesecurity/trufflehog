package demio

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

	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"demio"}) + `\b([a-z0-9A-Z]{32})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"demio"}) + `\b([a-z0-9A-Z]{10,20})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("demio")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	keyMatches := keyPat.FindAllSubmatch(data, -1)
	secretMatches := secretPat.FindAllSubmatch(data, -1)

	for _, match := range keyMatches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, idmatch := range secretMatches {
			if len(idmatch) != 2 {
				continue
			}
			resIdMatch := bytes.TrimSpace(idmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Demio,
				Raw:          resMatch,
			}

			if verify {
				url := fmt.Sprintf("https://my.demio.com/api/v1/ping/query?api_key=%s&api_secret=%s", string(resMatch), string(resIdMatch))

				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					continue
				}
				res, err := client.Do(req)
				if err != nil || res.StatusCode < 200 || res.StatusCode >= 300 {
					if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
						continue
					}
				} else {
					s1.Verified = true
				}
			}
			results = append(results, s1)
		}
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Demio
}
