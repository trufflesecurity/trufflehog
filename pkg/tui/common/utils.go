package common

import (
	"strings"

	"github.com/muesli/reflow/truncate"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

// TruncateString is a convenient wrapper around truncate.TruncateString.
func TruncateString(s string, max int) string {
	if max < 0 {
		max = 0
	}
	return truncate.StringWithTail(s, uint(max), "…")
}

func SummarizeSource(keys []string, inputs map[string]textinputs.Input, labels map[string]string) string {
	summary := strings.Builder{}
	for _, key := range keys {
		if inputs[key].Value != "" {
			summary.WriteString("\t" + labels[key] + ": " + inputs[key].Value + "\n")
		}
	}

	summary.WriteString("\n")
	return summary.String()
}
