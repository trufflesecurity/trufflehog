package detectors_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// bypassPatterns are stdlib HTTP entry points that bypass the shared
// transport chain (CustomTransport / detectorTransport) and therefore the
// --header CLI flag. Detectors must not use these directly; they should
// route through one of the helper functions in pkg/common or pkg/detectors
// so user-configured custom headers reach all verification traffic.
var bypassPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bhttp\.DefaultClient\b`),
	regexp.MustCompile(`\bhttp\.Get\(`),
	regexp.MustCompile(`\bhttp\.Post\(`),
	regexp.MustCompile(`\bhttp\.Head\(`),
	regexp.MustCompile(`\bhttp\.PostForm\(`),
}

// allowlistedFiles documents detectors that are intentionally excluded from
// the bypass check. Each entry must include the reason and the alternative
// mechanism by which the detector honors --header.
var allowlistedFiles = map[string]string{
	// AWS access keys uses aws-sdk-go-v2 which builds its own HTTP transport
	// stack. --header support is provided via applyCustomHeadersMiddleware
	// in pkg/detectors/aws/access_keys/accesskey.go (an SDK-level middleware),
	// not via the shared HTTP transport. The detector does not use any of
	// the bypass patterns above directly, but listing it here documents the
	// alternative mechanism and avoids surprise during code review.
}

// TestNoStdlibHTTPBypassInDetectors fails if any detector source file uses a
// stdlib HTTP entry point that bypasses the shared transport. This guards
// against silent regressions of --header coverage as new detectors are
// added. If a new detector legitimately requires SDK-managed HTTP (e.g.
// aws-sdk-go-v2, golang.org/x/oauth2 with explicit context client), add it
// to allowlistedFiles above with a clear note about how it honors --header.
func TestNoStdlibHTTPBypassInDetectors(t *testing.T) {
	detectorsRoot := "."
	type violation struct {
		path    string
		pattern string
		line    int
		text    string
	}
	var violations []violation

	err := filepath.Walk(detectorsRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// Skip the shared transport file itself; it legitimately references
		// http types when defining the transports.
		if filepath.Base(path) == "http.go" && filepath.Dir(path) == "." {
			return nil
		}
		// Normalize for allowlist comparison.
		rel := filepath.ToSlash(path)
		if _, ok := allowlistedFiles[rel]; ok {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			// Strip line-comment portion so commented references don't trip us.
			if idx := strings.Index(line, "//"); idx >= 0 {
				line = line[:idx]
			}
			for _, re := range bypassPatterns {
				if re.MatchString(line) {
					violations = append(violations, violation{
						path:    rel,
						pattern: re.String(),
						line:    i + 1,
						text:    strings.TrimSpace(lines[i]),
					})
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking detectors tree: %v", err)
	}

	if len(violations) > 0 {
		var msg strings.Builder
		msg.WriteString("found stdlib HTTP bypass in detector code; use a shared HTTP client helper from pkg/common or pkg/detectors so --header values reach verification traffic\n")
		for _, v := range violations {
			msg.WriteString("  ")
			msg.WriteString(v.path)
			msg.WriteString(":")
			msg.WriteString(itoa(v.line))
			msg.WriteString(" matched ")
			msg.WriteString(v.pattern)
			msg.WriteString("\n    ")
			msg.WriteString(v.text)
			msg.WriteString("\n")
		}
		t.Error(msg.String())
	}
}

// itoa avoids pulling in strconv solely for line numbers.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
