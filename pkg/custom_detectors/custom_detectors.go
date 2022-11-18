package custom_detectors

import "github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"

// customRegex is a CustomRegex that is guaranteed to be valid.
type customRegex *custom_detectorspb.CustomRegex

func NewCustomRegex(pb *custom_detectorspb.CustomRegex) (customRegex, error) {
	// TODO: validate
	return pb, nil
}
