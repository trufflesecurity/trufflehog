package api2cart

import (
	"bytes"
	"context"
	"encoding/json"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"api2cart"}) + `\b([0-9a-f]{32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("api2cart")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Api2Cart,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.api2cart.com/v1.1/account.cart.list.json?api_key=%s", string(resMatch)), nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/json")
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()

				var result Response
				err := json.NewDecoder(res.Body).Decode(&result)
				if err == nil && res.StatusCode >= 200 && res.StatusCode < 300 && result.ReturnCode == 0 {
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

type Response struct {
	ReturnCode int `json:"return_code"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Api2Cart
}
