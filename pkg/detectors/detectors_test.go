//go:build detectors
// +build detectors

package detectors

import (
	"testing"

	regexp "github.com/wasilibs/go-re2"
)

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

func TestPrefixRegexKeywords(t *testing.T) {
	keywords := []string{"keyword1", "keyword2", "keyword3"}

	testCases := []struct {
		input    string
		expected bool
	}{
		{"keyword1 1234c4aabceeff4444442131444aab44", true},
		{"keyword1 1234567890ABCDEF1234567890ABBBCA", false},
		{"KEYWORD1 1234567890abcdef1234567890ababcd", true},
		{"KEYWORD1 1234567890ABCDEF1234567890ABdaba", false},
		{"keyword2 1234567890abcdef1234567890abeeff", true},
		{"keyword2 1234567890ABCDEF1234567890ABadbd", false},
		{"KEYWORD2 1234567890abcdef1234567890ababca", true},
		{"KEYWORD2 1234567890ABCDEF1234567890ABBBBs", false},
		{"keyword3 1234567890abcdef1234567890abccea", true},
		{"KEYWORD3 1234567890abcdef1234567890abaabb", true},
		{"keyword4 1234567890abcdef1234567890abzzzz", false},
		{"keyword3 1234567890ABCDEF1234567890AB", false},
		{"keyword4 1234567890ABCDEF1234567890AB", false},
	}

	keyPat := regexp.MustCompile(PrefixRegex(keywords) + `\b([0-9a-f]{32})\b`)

	for _, tc := range testCases {
		match := keyPat.MatchString(tc.input)
		if match != tc.expected {
			t.Errorf("Input: %s, Expected: %v, Got: %v", tc.input, tc.expected, match)
		}
	}
}

func BenchmarkPrefixRegex(b *testing.B) {
	kws := []string{"securitytrails"}
	for i := 0; i < b.N; i++ {
		PrefixRegex(kws)
	}
}
