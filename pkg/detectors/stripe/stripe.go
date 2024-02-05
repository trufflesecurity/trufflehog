package stripe

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// doesn't include test keys with "sk_test"
	secretKey = regexp.MustCompile(`[rs]k_live_[a-zA-Z0-9]{20,247}`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"k_live"}
}

// FromData will find and optionally verify Stripe secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	dataStr := string(data)

	matches := secretKey.FindAllString(dataStr, -1)

	for _, match := range matches {

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Stripe,
			Raw:          []byte(match),
		}
		s.ExtraData = map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/stripe/",
		}

		if verify {

			baseURL := "https://api.stripe.com/v1/charges"

			client := common.SaneHttpClient()

			// test `read_user` scope
			req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", match))
			req.Header.Add("Content-Type", "application/json")
			res, err := client.Do(req)
			if err == nil {
				res.Body.Close() // The request body is unused.

				if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusForbidden {
					s.Verified = true
				}
			}
		}

		if !s.Verified && detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Stripe
}
