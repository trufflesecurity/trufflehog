package composio

import (
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

// Composio issues three key types, all a fixed prefix followed by URL-safe
// nanoid characters. oak_ and uak_ contain "ak_", so every pattern requires a
// non-alphabet character (or start of input) before the prefix. The trailing
// boundary is checked in code rather than in the pattern: a consuming trailing
// group would swallow the single delimiter between two adjacent keys and drop
// the second one.
type keyPattern struct {
	keyType string
	re      *regexp.Regexp
}

var keyPatterns = []keyPattern{
	{keyType: "project", re: regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(ak_[A-Za-z0-9_-]{20})`)},
	{keyType: "org", re: regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(oak_[A-Za-z0-9_-]{20})`)},
	{keyType: "user", re: regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(uak_[A-Za-z0-9_-]{43})`)},
}

// isKeyAlphabet reports whether b can appear inside a Composio key.
func isKeyAlphabet(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-'
}

// endsAtBoundary reports whether the key ending at end is followed by end of
// input or a character that cannot be part of a key.
func endsAtBoundary(data string, end int) bool {
	return end >= len(data) || !isKeyAlphabet(data[end])
}

// Keywords are used for efficiently pre-filtering chunks. "ak_" is a substring
// of all three prefixes.
func (s Scanner) Keywords() []string {
	return []string{"ak_"}
}

// FromData finds Composio API keys in a given set of bytes. Verification is not
// implemented yet; results are reported as unverified.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	seen := make(map[string]struct{})
	for _, pattern := range keyPatterns {
		for _, loc := range pattern.re.FindAllStringSubmatchIndex(dataStr, -1) {
			start, end := loc[2], loc[3]
			if !endsAtBoundary(dataStr, end) {
				continue
			}
			token := dataStr[start:end]
			if _, dup := seen[token]; dup {
				continue
			}
			seen[token] = struct{}{}

			results = append(results, detectors.Result{
				DetectorType: detector_typepb.DetectorType_Composio,
				Raw:          []byte(token),
				SecretParts:  map[string]string{"key": token},
				ExtraData: map[string]string{
					"key_type":       pattern.keyType,
					"rotation_guide": "https://docs.composio.dev/docs/api-keys",
				},
			})
		}
	}

	return results, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Composio
}

func (s Scanner) Description() string {
	return "Composio is an integration platform for AI agents. Composio API keys authenticate calls that execute tools, read connected accounts and manage triggers for a project, an organization or a user."
}
