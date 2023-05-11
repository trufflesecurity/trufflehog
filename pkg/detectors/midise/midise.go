package midise

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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	secretKey = regexp.MustCompile(`midi-662b69edd2[a-zA-Z0-9]{54}`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"midi-662b69edd2"}
}

// FromData will find and optionally verify Midise secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	dataStr := string(data)

	matches := secretKey.FindAllString(dataStr, -1)

	for _, match := range matches {

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Midise,
			Raw:          []byte(match),
		}

		if verify {

			baseURL := "https://hooks.zapier.com/hooks/catch/11693304/bssgr3k"

			client := common.SaneHttpClient()

			req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", match))
			req.Header.Add("Content-Type", "application/json")
			res, err := client.Do(req)
			if err == nil {
				res.Body.Close() // The request body is unused.

				if res.StatusCode == http.StatusOK {
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
	return detectorspb.DetectorType_Midise
}
