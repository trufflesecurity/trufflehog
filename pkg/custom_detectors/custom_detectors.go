package custom_detectors

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
)

// customRegexWebhook is a CustomRegex with webhook validation that is
// guaranteed to be valid.
type customRegexWebhook *custom_detectorspb.CustomRegex

func NewWebhookCustomRegex(pb *custom_detectorspb.CustomRegex) (customRegexWebhook, error) {
	// TODO: Return all validation errors.
	if err := ValidateKeywords(pb.Keywords); err != nil {
		return nil, err
	}
	if err := ValidateRegex(pb.Regex); err != nil {
		return nil, err
	}

	for _, verify := range pb.Verify {
		if err := ValidateVerifyEndpoint(verify.Endpoint, verify.Unsafe); err != nil {
			return nil, err
		}
		if err := ValidateVerifyHeaders(verify.Headers); err != nil {
			return nil, err
		}
	}

	return pb, nil
}
