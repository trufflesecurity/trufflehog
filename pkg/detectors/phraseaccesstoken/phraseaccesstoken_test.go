package phraseaccesstoken

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890"
	invalidPattern = "7cf4135a4e7f7ac228d36f210f151917a86f5dbd6"
	keyword        = "phrase"
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
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("%s token = '%s' | '%s'", keyword, validPattern, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s'", keyword, validPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s = '%s'", keyword, invalidPattern),
			want:  []string{},
		},
		{
			name:  "finds all valid matches",
			input: fmt.Sprintf("%s token1 = '%s'\n%s token2 = '%s'", keyword, validPattern, keyword, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
			want:  []string{validPattern, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
		},
		{
			name:  "invalid pattern - too short",
			input: fmt.Sprintf("%s = '%s'", keyword, "1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678"),
			want:  []string{},
		},
		{
			name:  "invalid pattern - too long",
			input: fmt.Sprintf("%s = '%s'", keyword, "1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef123456789012"),
			want:  []string{},
		},
		{
			name:  "invalid pattern - contains uppercase",
			input: fmt.Sprintf("%s = '%s'", keyword, "1A2B3C4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890"),
			want:  []string{},
		},
		{
			name:  "invalid pattern - contains special characters",
			input: fmt.Sprintf("%s = '%s'", keyword, "1a2b3c4d-e6f7890abcdef1234567890abcdef1234567890abcdef1234567890"),
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
