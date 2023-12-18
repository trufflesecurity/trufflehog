package npm

import (
	"context"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type ScannerV1 struct {
	npmScanner
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ interface {
	detectors.Detector
	detectors.Versioner
} = (*ScannerV1)(nil)

func (s ScannerV1) Version() int { return 1 }

// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
var v1KeyPat = regexp.MustCompile(`(?:NpmToken\.|` + detectors.PrefixRegex([]string{"npm"}) + `)\b(?i)([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s ScannerV1) Keywords() []string {
	return []string{"npm"}
}

// FromData will find and optionally verify NpmToken secrets in a given set of bytes.
func (s ScannerV1) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Deduplicate results for more efficient handling.
	tokens := make(map[string]struct{})
	for _, match := range v1KeyPat.FindAllStringSubmatch(dataStr, -1) {
		tokens[match[1]] = struct{}{}
	}
	if len(tokens) == 0 {
		return
	}

	for token := range tokens {
		s1 := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(token),
		}

		if verify {
			verified, extraData, vErr := s.verifyToken(ctx, dataStr, token)
			s1.Verified = verified
			s1.ExtraData = extraData
			s1.SetVerificationError(vErr)
		}

		results = append(results, s1)
	}
	return
}

func (s ScannerV1) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_NpmToken
}

func (s ScannerV1) Description() string {
	return "NPM tokens are used to authenticate and publish packages to the npm registry."
}
