package stripewebhook

import (
	"context"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	detector_typepb "github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	Client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// whsec_ followed by 32 or 64 base64-style characters
	keyPat = regexp.MustCompile(`\b(whsec_[A-Za-z0-9+/]{32}(?:[A-Za-z0-9+/]{32})?)\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"whsec_"}
}

func (s Scanner) Description() string {
	return "Stripe Webhook Secrets are used to verify that webhook events are sent by Stripe. Exposure allows attackers to forge webhook events."
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_StripeWebhook
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := match[1]

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_StripeWebhook,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.Client
			if client == nil {
				client = defaultClient
			}
			_ = client
			// Stripe webhook secrets cannot be verified via API directly.
			// They are used client-side to validate HMAC signatures on webhooks.
		}

		results = append(results, s1)
	}

	return results, nil
}
