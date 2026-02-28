package common

import (
	"os"
)

// ExpandEnvSafe expands environment variables in s, while intentionally avoiding
// shell-special expansions that are common in regex patterns and YAML comments.
//
// Supported expansions:
//   - $VAR
//   - ${VAR}
//
// Where VAR matches: [A-Za-z_][A-Za-z0-9_]*
//
// Notably, it does NOT expand:
//   - shell special parameters like $? / $@ / $1
//   - incomplete brace forms like "${VAR" (missing closing brace)
//   - non-identifier forms like "$(cmd)"
//
// If '$' is preceded by an odd number of backslashes (e.g. "\$FOO"), it is
// treated as escaped and will not be expanded.
func ExpandEnvSafe(s string) string {
	return expandEnvSafe(s, os.Getenv)
}

func expandEnvSafe(s string, getenv func(string) string) string {
	if s == "" {
		return s
	}

	// Build lazily to avoid allocations when no expansions happen.
	out := make([]byte, 0, len(s))
	changed := false

	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			out = append(out, s[i])
			continue
		}

		// If '$' is escaped (odd number of backslashes immediately preceding),
		// keep it literal.
		if isEscapedDollar(s, i) {
			out = append(out, '$')
			continue
		}

		// Need at least one character after '$' to expand.
		if i+1 >= len(s) {
			out = append(out, '$')
			continue
		}

		// ${VAR} form (only if there is a closing brace).
		if s[i+1] == '{' {
			end := indexByteFrom(s, '}', i+2)
			if end == -1 {
				// Incomplete; treat as literal.
				out = append(out, '$')
				continue
			}
			name := s[i+2 : end]
			if isEnvVarName(name) {
				out = append(out, getenv(name)...)
				changed = true
				i = end
				continue
			}

			// Not a valid env var name; keep literal.
			out = append(out, s[i:end+1]...)
			i = end
			continue
		}

		// $VAR form.
		if isEnvVarNameStart(s[i+1]) {
			j := i + 2
			for j < len(s) && isEnvVarNameChar(s[j]) {
				j++
			}
			name := s[i+1 : j]
			out = append(out, getenv(name)...)
			changed = true
			i = j - 1
			continue
		}

		// Otherwise treat '$' literally (covers $?, $@, $1, $(, $$, etc).
		out = append(out, '$')
	}

	if !changed {
		return s
	}
	return string(out)
}

func indexByteFrom(s string, b byte, start int) int {
	for i := start; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func isEnvVarNameStart(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '_'
}

func isEnvVarNameChar(b byte) bool {
	return isEnvVarNameStart(b) || (b >= '0' && b <= '9')
}

func isEnvVarName(name string) bool {
	if name == "" {
		return false
	}
	if !isEnvVarNameStart(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !isEnvVarNameChar(name[i]) {
			return false
		}
	}
	return true
}

func isEscapedDollar(s string, dollarIdx int) bool {
	// Count consecutive backslashes immediately before '$'.
	n := 0
	for i := dollarIdx - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

