package stripe

import (
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
	secretKey = regexp.MustCompile(`[rs]k_live_[a-zA-Z0-9]{20,30}`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("k_live")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := secretKey.FindAll(data, -1)

	for _, match := range matches {

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Stripe,
			Raw:          match,
		}

		if verify {

			baseURL := []byte("https://api.stripe.com/v1/charges")
			client := common.SaneHttpClient()

			req, err := http.NewRequestWithContext(ctx, "GET", string(baseURL), nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(match)))
			req.Header.Add("Content-Type", "application/json")
			res, err := client.Do(req)
			if err == nil {
				res.Body.Close()

				if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusForbidden {
					s1.Verified = true
				}
			}
		}

		if !s1.Verified && detectors.IsKnownFalsePositive(match, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Stripe
}
