package engine

import (
	"testing"
)

func TestGetParanoidDetectors(t *testing.T) {
	tests := []struct {
		name               string
		targets            []string
		oneOrMoreDetectors bool
	}{
		{
			name:               "Empty targets",
			targets:            []string{},
			oneOrMoreDetectors: false,
		},
		{
			name:               "32 character string",
			targets:            []string{"12345678901234567890123456789012"},
			oneOrMoreDetectors: true,
		},
	}

	pc := NewParanoidCore(DefaultDetectors())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pc.getParanoidDetectors(tt.targets)
			if tt.oneOrMoreDetectors {
				if len(got) == 0 {
					t.Errorf("getParanoidDetectors() = %v, want at least one paranoid detector", got)
				}
			} else {
				if len(got) > 0 {
					t.Errorf("getParanoidDetectors() = %v, expecting 0 paranoid detectors", got)
				}

			}
		})
	}
}

func TestChecks(t *testing.T) {
	tests := []struct {
		name     string
		word     string
		entropy  float32
		expected bool
	}{
		{
			name:     "Valid case",
			word:     "8dyfuiRyq=vVc3RRr_edRk-fK__JItpZ",
			entropy:  3.5,
			expected: true,
		},
		{
			name:     "Invalid case",
			word:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			entropy:  3.5,
            expected: false,
		},
		{
			name:     "Invalid case stopwords",
			word:     "thiscontainsword8dyfuiRyq=vVc3RR",
			entropy:  3.5,
            expected: false,
		},
	}

	pc := NewParanoidCore(DefaultDetectors())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pc.checks(tt.word, tt.entropy)
			// Compare result with tt.expected
			if result != tt.expected {
				t.Errorf("checks() = %v, want %v", result, tt.expected)
			}
		})
	}
}
