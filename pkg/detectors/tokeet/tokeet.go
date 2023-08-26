package tokeet

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"tokeet"}) + `\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"tokeet"}) + `\b([0-9]{10}.[0-9]{4})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("tokeet")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	keyMatches := keyPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)

	for _, keyMatch := range keyMatches {
		if len(keyMatch) != 2 {
			continue
		}

		key := bytes.TrimSpace(keyMatch[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}

			id := bytes.TrimSpace(idMatch[1])

			result := detectors.Result{
				DetectorType: detectorspb.DetectorType_Tokeet,
				Raw:          key,
			}

			if verify {
				req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://capi.tokeet.com/v1/user?account=%s", id), nil)
				req.Header.Add("Accept", "application/json")
				req.Header.Add("Authorization", string(key))
				res, _ := client.Do(req)
				defer res.Body.Close()

				if res.StatusCode >= 200 && res.StatusCode < 300 {
					result.Verified = true
				} else {
					if detectors.IsKnownFalsePositive(key, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}

			results = append(results, result)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Tokeet
}
