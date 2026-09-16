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
// non-alphabet character (or start of input) before the prefix, and a
// non-alphabet character (or end of input) after the key.
type keyPattern struct {
	keyType string
	re      *regexp.Regexp
}

var keyPatterns = []keyPattern{
	{keyType: "project", re: regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(ak_[A-Za-z0-9_-]{20})(?:[^A-Za-z0-9_-]|$)`)},
	{keyType: "org", re: regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(oak_[A-Za-z0-9_-]{20})(?:[^A-Za-z0-9_-]|$)`)},
	{keyType: "user", re: regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(uak_[A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`)},
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
		for _, match := range pattern.re.FindAllStringSubmatch(dataStr, -1) {
			token := match[1]
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
