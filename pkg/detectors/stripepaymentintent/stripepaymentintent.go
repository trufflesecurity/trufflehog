package stripepaymentintent

import (
	"context"
	"errors"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`(pi_[a-zA-Z0-9]{24}_secret_[a-zA-Z0-9]{25})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"pi_", "_secret_"}
}

// FromData will find and optionally verify Stripepaymentintent secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	var uniqueKeys = make(map[string]struct{})

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[matches[1]] = struct{}{}
	}

	for match := range uniqueKeys {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_StripePaymentIntent,
			Raw:          []byte(match),
			Verified:     false,
		}
		s1.SetVerificationError(errors.New("unable to verify as the verification requires a valid Stripe secret/publishable key"), match)

		results = append(results, s1)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_StripePaymentIntent
}

func (s Scanner) Description() string {
	return "Stripepaymentintent objects represent a customer's intent to pay and track the lifecycle of a payment. These objects are used to initiate and manage payment flows, including confirmation, authentication, and capture of funds."
}
