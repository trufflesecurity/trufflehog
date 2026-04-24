package stripewebhooksecret

import (
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// No trailing \b: webhook secrets are base64-style and may end with '+',
// which is a non-word char that breaks \b. The {32,64} greedy quantifier
// combined with the restrictive char class is sufficient to delimit matches.
var keyPat = regexp.MustCompile(`\b(whsec_[A-Za-z0-9+]{32,64})`)

func (s Scanner) Keywords() []string {
	return []string{"whsec_"}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		results = append(results, detectors.Result{
			DetectorType: detector_typepb.DetectorType_StripeWebhookSecret,
			Raw:          []byte(match),
		})
	}

	return results, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_StripeWebhookSecret
}

func (s Scanner) Description() string {
	return "Stripe webhook signing secrets (whsec_...) are used to verify the authenticity of webhook events sent from Stripe."
}
