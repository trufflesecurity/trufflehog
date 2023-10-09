//go:build detectors
// +build detectors

package detectors

import "testing"

func TestPrefixRegex(t *testing.T) {
	tests := []struct {
		keywords []string
		expected string
	}{
		{
			keywords: []string{"securitytrails"},
			expected: `(?i)(?:securitytrails)(?:.|[\n\r]){0,40}`,
		},
		{
			keywords: []string{"zipbooks"},
			expected: `(?i)(?:zipbooks)(?:.|[\n\r]){0,40}`,
		},
		{
			keywords: []string{"wrike"},
			expected: `(?i)(?:wrike)(?:.|[\n\r]){0,40}`,
		},
	}
	for _, tt := range tests {
		got := PrefixRegex(tt.keywords)
		if got != tt.expected {
			t.Errorf("PrefixRegex(%v) got: %v want: %v", tt.keywords, got, tt.expected)
		}
	}
}

func BenchmarkPrefixRegex(b *testing.B) {
	kws := []string{"securitytrails"}
	for i := 0; i < b.N; i++ {
		PrefixRegex(kws)
	}
}
