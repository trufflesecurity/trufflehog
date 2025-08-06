package phraseaccesstoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestPhrase_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword phrase",
			input: "phrase token = 1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890",
			want:  []string{"1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890"},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: "phrase token = '1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890' | '1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'",
			want:  []string{"1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890"},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: "phrase keyword is not close to the real key in the data\n = '1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'",
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: "phrase = 7cf4135a4e7f7ac228d36f210f151917a86f5dbd6",
			want:  []string{},
		},
		{
			name:  "finds all valid matches",
			input: "phrase token1 = '1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'\n  phrase token2 = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'",
			want:  []string{"1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
		},
		{
			name:  "invalid pattern - too short",
			input: "phrase = '1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678'",
			want:  []string{},
		},
		{
			name:  "invalid pattern - too long",
			input: "phrase = '1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef123456789012'",
			want:  []string{},
		},
		{
			name:  "invalid pattern - contains uppercase",
			input: "phrase = '1A2B3C4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'",
			want:  []string{},
		},
		{
			name:  "invalid pattern - contains special characters",
			input: "phrase = '1a2b3c4d-e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'",
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}
