package frameworksecret

import (
	"context"
	"math"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

const (
	// Minimum Shannon entropy for a secret to be considered valid.
	// This filters out placeholders like "changeme", "your_secret_here", etc.
	// Typical real secrets have entropy > 4.0, we use 3.5 to be safe.
	minEntropy = 3.5

	// Redaction: show first N and last M characters
	redactPrefixLen = 8
	redactSuffixLen = 4
)

// Framework secret patterns - ordered by specificity (most specific first)
// to avoid overlapping matches.
var (
	// Rails SECRET_KEY_BASE: 64-128 character hex string
	// Must be checked BEFORE Django to avoid SECRET_KEY matching it
	// Example: SECRET_KEY_BASE=abc123def456...
	railsPat = regexp.MustCompile(`(?i)(?:^|[^A-Z_])SECRET_KEY_BASE\s*[=:]\s*['"]?([a-f0-9]{64,128})['"]?`)

	// Symfony APP_SECRET: 32+ character hex string
	// Example: APP_SECRET=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
	symfonyPat = regexp.MustCompile(`(?i)(?:^|[^A-Z_])APP_SECRET\s*[=:]\s*['"]?([a-f0-9]{32,64})['"]?`)

	// Laravel APP_KEY: base64-encoded 32-byte key with "base64:" prefix
	// Example: APP_KEY=base64:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY=
	// Note: We use (?:^|[^A-Z_]) instead of \b to allow matching after quotes
	laravelPat = regexp.MustCompile(`(?i)(?:^|[^A-Z_])APP_KEY\s*[=:,]\s*['"]?(base64:[A-Za-z0-9+/]{42,44}={0,2})['"]?`)

	// Django SECRET_KEY: 50+ characters, must be quoted (to reduce false positives)
	// Example: SECRET_KEY='django-insecure-abc123...' or SECRET_KEY="complex-key-here"
	// Note: We require quotes to distinguish from generic SECRET_KEY usage
	djangoPat = regexp.MustCompile(`(?i)(?:^|[^A-Z_])SECRET_KEY\s*[=:]\s*['"]([^'"]{50,128})['"]`)
)

// frameworkInfo contains metadata about each framework's secret.
// Order matters: more specific patterns should come first.
type frameworkInfo struct {
	pattern   *regexp.Regexp
	framework string
	variable  string
	docs      string
	// minLen is the minimum length for the captured secret (post-regex)
	minLen int
	// exactEntropy: if true, use entropy check; hex strings have ~4.0 entropy naturally
	checkEntropy bool
}

// frameworks is ordered by specificity - Rails first to prevent Django matching SECRET_KEY_BASE
var frameworks = []frameworkInfo{
	{
		pattern:      railsPat,
		framework:    "Rails",
		variable:     "SECRET_KEY_BASE",
		docs:         "https://guides.rubyonrails.org/security.html#session-storage",
		minLen:       64,
		checkEntropy: false, // hex strings naturally have high entropy
	},
	{
		pattern:      symfonyPat,
		framework:    "Symfony",
		variable:     "APP_SECRET",
		docs:         "https://symfony.com/doc/current/reference/configuration/framework.html#secret",
		minLen:       32,
		checkEntropy: false, // hex strings naturally have high entropy
	},
	{
		pattern:      laravelPat,
		framework:    "Laravel",
		variable:     "APP_KEY",
		docs:         "https://laravel.com/docs/master/encryption",
		minLen:       49,    // "base64:" (7) + 42 chars minimum
		checkEntropy: false, // base64 has high entropy by nature
	},
	{
		pattern:      djangoPat,
		framework:    "Django",
		variable:     "SECRET_KEY",
		docs:         "https://docs.djangoproject.com/en/stable/ref/settings/#secret-key",
		minLen:       50,
		checkEntropy: true, // Django allows various formats, entropy check needed
	},
}

// Keywords are used for efficiently pre-filtering chunks.
// More specific keywords reduce unnecessary regex matching.
func (s Scanner) Keywords() []string {
	return []string{
		"SECRET_KEY_BASE", // Rails - most specific, check first
		"APP_SECRET",      // Symfony
		"APP_KEY",         // Laravel
		"SECRET_KEY",      // Django - least specific, check last
	}
}

// FromData finds framework secret keys in the given bytes.
// These secrets cannot be verified via API, so they are always returned as unverified.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Track matched positions to avoid duplicate detections
	// (e.g., SECRET_KEY_BASE shouldn't also match as SECRET_KEY)
	matchedPositions := make(map[int]struct{})

	for _, fw := range frameworks {
		matches := fw.pattern.FindAllStringSubmatchIndex(dataStr, -1)

		for _, matchIdx := range matches {
			if len(matchIdx) < 4 {
				continue
			}

			// matchIdx[0:2] is full match, matchIdx[2:4] is capture group 1
			startPos := matchIdx[2]
			endPos := matchIdx[3]

			// Skip if this position was already matched by a more specific pattern
			if _, exists := matchedPositions[startPos]; exists {
				continue
			}

			secret := strings.TrimSpace(dataStr[startPos:endPos])

			// Length validation
			if len(secret) < fw.minLen {
				continue
			}

			// Entropy check for formats that need it (Django)
			if fw.checkEntropy && shannonEntropy(secret) < minEntropy {
				continue
			}

			// Skip obvious placeholders
			if isPlaceholder(secret) {
				continue
			}

			// Mark this position as matched
			matchedPositions[startPos] = struct{}{}

			result := detectors.Result{
				DetectorType: detectorspb.DetectorType_FrameworkSecretKey,
				Raw:          []byte(secret),
				Redacted:     redactSecret(secret),
				ExtraData: map[string]string{
					"framework":     fw.framework,
					"variable":      fw.variable,
					"documentation": fw.docs,
				},
			}

			results = append(results, result)
		}
	}

	return results, nil
}

// shannonEntropy calculates the Shannon entropy of a string.
// Higher entropy = more random = more likely to be a real secret.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	charCount := make(map[rune]int)
	for _, c := range s {
		charCount[c]++
	}

	entropy := 0.0
	length := float64(len(s))
	for _, count := range charCount {
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

// redactSecret returns a redacted version of the secret for display.
// Example: "a1b2c3d4...****e5f6" for a 32-char secret
func redactSecret(secret string) string {
	if len(secret) <= redactPrefixLen+redactSuffixLen {
		return strings.Repeat("*", len(secret))
	}

	prefix := secret[:redactPrefixLen]
	suffix := secret[len(secret)-redactSuffixLen:]
	middle := strings.Repeat("*", 4)

	return prefix + "..." + middle + suffix
}

// isPlaceholder checks if the secret looks like a placeholder value.
// We keep this minimal since entropy check handles most cases.
func isPlaceholder(secret string) bool {
	lower := strings.ToLower(secret)

	// Check for repeating characters (e.g., "aaaa..." or "1111...")
	if len(secret) >= 10 {
		first := rune(secret[0])
		allSame := true
		for _, c := range secret[1:20] { // Check first 20 chars
			if c != first {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}

	// Environment variable references
	if strings.HasPrefix(secret, "${") || strings.HasPrefix(lower, "$env:") {
		return true
	}

	// Template syntax
	if strings.Contains(secret, "{{") && strings.Contains(secret, "}}") {
		return true
	}

	return false
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FrameworkSecretKey
}

func (s Scanner) Description() string {
	return "Framework secret keys (Symfony APP_SECRET, Laravel APP_KEY, Django SECRET_KEY, Rails SECRET_KEY_BASE) are used for session signing, CSRF protection, and encryption. Exposed keys allow attackers to forge sessions, bypass CSRF, and potentially achieve RCE."
}

// IsFalsePositive implements CustomFalsePositiveChecker for additional filtering.
func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	secret := string(result.Raw)

	// Laravel keys start with "base64:" which would match the "base" wordlist entry.
	// Skip the default false positive check for Laravel keys.
	if strings.HasPrefix(secret, "base64:") {
		return false, ""
	}

	// Use TruffleHog's built-in false positive detection for other frameworks
	if isFP, reason := detectors.IsKnownFalsePositive(secret, detectors.DefaultFalsePositives, true); isFP {
		return true, reason
	}

	return false, ""
}
