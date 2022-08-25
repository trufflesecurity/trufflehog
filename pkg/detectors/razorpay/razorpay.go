package razorpay

import (
	"context"
	"regexp"

	log "github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/razorpay/razorpay-go"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

//The (`) character adds secondary encoding to parsed strings by Golang which also allows for escape sequences
var (
	keyPat    = regexp.MustCompile(`(?i)\brzp_\w{2,6}_\w{10,20}\b`)
	secretPat = regexp.MustCompile(`(?:razor|secret|rzp|key)[-\w]*[\" :=']*([A-Za-z0-9]{20,50})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"rzp_"}
}

// FromData will find and optionally verify RazorPay secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllString(dataStr, -1)

	for _, match := range matches {
		token := match

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_RazorPay,
			Raw:          []byte(token),
			Redacted:     token,
		}

		if verify {
			//https://dashboard.razorpay.com/#/access/signin
			//https://gitlab.com/trufflesec/trufflehog/-/blob/master/webapi/secrets/razorpay.py
			secMatches := secretPat.FindAllStringSubmatch(dataStr, -1)
			if len(secMatches) == 0 {
				//no secret keys were found. Declare unverified (This is how AWS secret handles the same logic)
				//TODO determine if key alone without secret is reportable
				s.Verified = false
				return
			}
			//we only want the secret, not its surrounding info - grabbing capture groups
			for _, secMatch := range secMatches {
				client := razorpay.NewClient(token, secMatch[1])
				resp, err := client.Order.All(nil, nil)
				//TODO Error handling is broken in SDK, fixed by https://github.com/razorpay/razorpay-go/pull/23
				//waiting to be reviewed and merged
				if resp == nil {
					continue
				}
				if err != nil {
					log.Debugf("Error verifying likely razorpay key/secret combo: %v", err)
					continue
				}
				//TODO debug with responses. could still be invalid at this stage

				s.Verified = true
				// fmt.Println(resp)
			}
		}

		if !s.Verified {
			if detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, false) {
				continue
			}
		}

		results = append(results, s)
	}

	return
}
