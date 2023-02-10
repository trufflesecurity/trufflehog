package common

import "github.com/muesli/reflow/truncate"

// TruncateString is a convenient wrapper around truncate.TruncateString.
func TruncateString(s string, max int) string {
	if max < 0 {
		max = 0
	}
	return truncate.StringWithTail(s, uint(max), "…")
}
