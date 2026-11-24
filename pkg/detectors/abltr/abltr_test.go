package abltr

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAbltr_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: "ABLTR_API_KEY=abltr-ai-46c2d93b597498cfa104c8a7f63ab2fd834bf0c2a23ac4ea40eedaa61d8beb50",
			want:  []string{"abltr-ai-46c2d93b597498cfa104c8a7f63ab2fd834bf0c2a23ac4ea40eedaa61d8beb50"},
		},
		{
			name:  "invalid too short",
			input: "abltr-ai-1be08f189bd12f42880fd2c8450d44f0",
			want:  []string{},
		},
		{
			name:  "invalid non-hex",
			input: "abltr-ai-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
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
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				actual[string(r.Raw)] = struct{}{}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, w := range test.want {
				expected[w] = struct{}{}
			}
			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
