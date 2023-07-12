package common

import (
	"strings"

	"github.com/muesli/reflow/truncate"
)

// TruncateString is a convenient wrapper around truncate.TruncateString.
func TruncateString(s string, max int) string {
	if max < 0 {
		max = 0
	}
	return truncate.StringWithTail(s, uint(max), "…")
}

func SummarizeSource(keys []string, inputs map[string]string, labels map[string]string) string {
	summary := strings.Builder{}
	for _, key := range keys {
		if inputs[key] != "" {
			summary.WriteString("\t" + labels[key] + ": " + inputs[key] + "\n")
		}
	}

	summary.WriteString("\n")
	return summary.String()
}
