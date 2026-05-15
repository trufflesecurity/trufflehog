package clay

import (
	"context"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	// keyPat matches an opaque token of 24-120 characters from the URL-safe
	// alphabet ([A-Za-z0-9_-]) that appears within 40 characters of the
	// literal substring "clay" (case-insensitive). This covers the common
	// naming variants: CLAY_API_KEY, clay_api_key, clayApiKey, clay-key,
	// clayKey, JSON {"clay": {"apiKey": "..."}}, YAML clay:\n  api_key: ...,
	// and .env CLAY_TOKEN=... shapes.
	//
	// Clay does not publish a public API key grammar (see
	// https://university.clay.com/docs/guide-find-clay-api-key), so the
	// match is intentionally broad. False positives are suppressed via an
	// entropy threshold and a placeholder deny-list inside FromData.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"clay"}) + `\b([A-Za-z0-9_\-]{24,120})\b`)

	// placeholders is a small deny-list of common placeholder fragments that
	// pass the structural regex but are clearly not real secrets. The match
	// is case-insensitive and substring-based.
	placeholders = []string{
		"your_clay_api_key",
		"your_api_key",
		"your-api-key",
		"your_clay_key",
		"example",
		"placeholder",
		"redacted",
		"xxxxxxxx",
		"changeme",
		"clay_api_key_here",
	}
)

// Keywords are used as a cheap prefilter (Aho-Corasick) before the regex
// runs. A single "clay" keyword catches every snake_case / camelCase /
// kebab-case / SCREAMING_SNAKE_CASE variant via case-insensitive substring
// matching.
func (s Scanner) Keywords() []string {
	return []string{"clay"}
}

// FromData extracts Clay API key candidates from data. Verification is not
// implemented in v1 because Clay does not document a stable, side-effect-
// free key-introspection endpoint; results land as Verified=false candidates.
func (s Scanner) FromData(_ context.Context, _ bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		token := strings.TrimSpace(match[1])
		if !isPlausibleSecret(token) {
			continue
		}
		uniqueMatches[token] = struct{}{}
	}

	for token := range uniqueMatches {
		results = append(results, detectors.Result{
			DetectorType: detector_typepb.DetectorType_Clay,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"key": token},
		})
	}

	return results, nil
}

// isPlausibleSecret applies entropy and placeholder filters so that obvious
// non-secrets (low-entropy strings, common placeholders) do not produce
// findings. Threshold of 3.5 bits/byte is empirically high enough to reject
// repetitive placeholder text while admitting realistic high-entropy
// opaque tokens.
func isPlausibleSecret(token string) bool {
	if detectors.StringShannonEntropy(token) < 3.5 {
		return false
	}
	lower := strings.ToLower(token)
	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return false
		}
	}
	return true
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Clay
}

func (s Scanner) Description() string {
	return "Clay is a go-to-market platform for data enrichment and outbound automation. Clay API keys grant access to a user's workspace tables, integrations, and stored third-party credentials."
}
