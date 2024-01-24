package mailchimp

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()
	keyPat = regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"-us"}
}

// FromData will find and optionally verify Mailchimp secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// pretty standard regex match
	matches := keyPat.FindAllString(dataStr, -1)

	for _, match := range matches {

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Mailchimp,
			Raw:          []byte(match),
		}
		s.ExtraData = map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/mailchimp/",
		}

		if verify {
			datacenter := strings.Split(match, "-")[1]

			// https://mailchimp.com/developer/guides/marketing-api-conventions/
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s.api.mailchimp.com/3.0/", datacenter), nil)
			if err != nil {
				continue
			}
			req.SetBasicAuth("anystring", match)
			req.Header.Add("accept", "application/json")
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s.Verified = true
				} else {
					// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
					if detectors.IsKnownFalsePositive(match, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}
		}

		results = append(results, s)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Mailchimp
}
