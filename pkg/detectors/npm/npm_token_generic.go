package npm

import (
	"context"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type ScannerGeneric struct {
	npmScanner
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ interface {
	detectors.Detector
	detectors.Versioner
} = (*ScannerGeneric)(nil)

func (s ScannerGeneric) Version() int { return 0 }

// genericKeyPat should match all possible values for .npmrc auth tokens.
// TODO: Ensure this works with Yarn and UPM configurations.
var genericKeyPat = regexp.MustCompile(`(?:_authToken|(?i:npm[_\-.]?token))['"]?[ \t]*[=:]?(?:[ \t]*['"]?)?([a-zA-Z0-9\-_.+=/]{5,})`)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s ScannerGeneric) Keywords() []string {
	return []string{"_authToken", "npm_token", "npm-token", "npm.token"}
}

// FromData will find and optionally verify secrets in a given set of bytes.
func (s ScannerGeneric) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Deduplicate results for more efficient handling.
	tokens := make(map[string]struct{})
	for _, match := range genericKeyPat.FindAllStringSubmatch(dataStr, -1) {
		t := match[1]
		// Ignore results that can be handled by the v1 or v2 detectors.
		if strings.HasPrefix(t, "NpmToken.") || strings.HasPrefix(t, "npm_") {
			continue
		}
		tokens[t] = struct{}{}
	}
	if len(tokens) == 0 {
		return
	}

	// Iterate through results.
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

func (s ScannerGeneric) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_NpmToken
}

func (s ScannerGeneric) Description() string {
	return "NPM tokens are used to authenticate and publish packages to the npm registry."
}
