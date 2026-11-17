package privatekey

import (
	"strings"
)

// escapeReplacer converts a variety of platform‐specific and escaped
// whitespace sequences into a canonical representation.
// The order of the patterns matters: the double-escaped forms (e.g. "\\n")
// must be replaced before the single-escaped forms ("\n") so that each
// sequence is handled exactly once.
var escapeReplacer = strings.NewReplacer(
	`\\n`, "\n",     // Double-escaped newlines
	`\n`, "\n",      // Single-escaped newlines
	`\\r\\n`, "\n",  // Double-escaped CRLF
	`\r\n`, "\n",    // Escaped CRLF
	"\r\n", "\n",    // Actual CRLF
	`\\r`, "\n",     // Double-escaped CR
	`\r`, "\n",      // Escaped CR
	"\r", "\n",      // Actual CR
	`\\t`, "",       // Double-escaped tabs
	`\t`, "",        // Escaped tabs
	"\t", "",        // Actual tabs
)

// Normalize prepares a raw private-key string for parsing.
//
// Normalize applies a best-effort cleanup so that keys copied from environment
// variables, JSON blobs, or other text formats are converted into a form that
// Go's crypto/x509 and crypto/ssh parsers can consume reliably. It performs the
// following steps:
//
//   1. Trim leading and trailing whitespace.
//   2. Remove a single layer of surrounding single or double quotes.
//   3. Replace escaped or platform-specific newline/carriage-return/tab
//      sequences with a canonical "\n", removing tabs entirely.
//   4. Split the text on "\n", trim each line, drop empty lines, and rejoin
//      the remainder with a trailing newline.
//
// The function never returns an error; if "in" is already well-formed, it is
// returned unchanged (apart from guaranteeing a trailing newline).
func Normalize(raw string) string {
	raw = strings.TrimSpace(raw)

	// Remove surrounding quotes if present.
	if len(raw) >= 2 {
		if (raw[0] == '"' && raw[len(raw)-1] == '"') ||
			(raw[0] == '\'' && raw[len(raw)-1] == '\'') {
			raw = raw[1 : len(raw)-1]
		}
	}

	// Canonicalize escape sequences in one pass.
	raw = escapeReplacer.Replace(raw)

	var result strings.Builder
	result.Grow(len(raw))

	// Normalize per-line whitespace and discard blank lines.
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			result.WriteString(trimmed)
			result.WriteByte('\n')
		}
	}

	return result.String()
}
