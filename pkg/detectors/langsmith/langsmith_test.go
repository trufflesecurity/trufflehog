package langsmith

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestLangsmith_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: "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",
			want:  []string{"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"},
		},
		{
			name:  "finds all matches",
			input: `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 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`,
			want:  []string{"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", "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"},
		},
		{
			name:  "invalid pattern",
			input: "lsv2_pt_1e0430d40fc14d3fj03397b9e6z46289_2b9036edd2",
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
