package onepasswordserviceaccount

import (
	"context"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// The prefix is part of the token itself, so no PrefixRegex wrapper needed.
	// No trailing \b since tokens are Base64 and may end with non-word chars (=, -, +, /).
	keyPat = regexp.MustCompile(`(ops_eyJ[A-Za-z0-9+/=._-]{50,})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ops_eyJ"}
}

// FromData will find and optionally verify OnepasswordServiceAccount secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		m := strings.TrimSpace(match[1])
		uniqueMatches[m] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_OnepasswordServiceAccount,
			Raw:          []byte(match),
		}

		// 1Password service account tokens use SRP authentication and cannot be
		// verified with a simple HTTP request. Pattern match only.

		results = append(results, s1)
	}

	return
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_OnepasswordServiceAccount
}

func (s Scanner) Description() string {
	return "1Password service account tokens are used to authenticate automated workflows and CI/CD pipelines with 1Password vaults. These tokens use SRP-based authentication and grant access to secrets stored in assigned vaults."
}
