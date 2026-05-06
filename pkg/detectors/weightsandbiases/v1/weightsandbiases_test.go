package weightsandbiases

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestWeightsandbiases_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: "WANDB_API_KEY = 'eedf1c984f6b995ec40ecc6658356044847ffb31'",
			want:  []string{"eedf1c984f6b995ec40ecc6658356044847ffb31"},
		},
		{
			name: "finds all matches",
			input: `WANDB_API_KEY = 'eedf1c984f6b995ec40ecc6658356044847ffb31'
WANDB_API_KEY= 'eedf1c984f6b995ec40ecc6658356044847ffb32'`,
			want: []string{"eedf1c984f6b995ec40ecc6658356044847ffb31", "eedf1c984f6b995ec40ecc6658356044847ffb32"},
		},
		{
			name:  "invalid pattern",
			input: "WANDB_API_KEY = 'e84f6b995ec40ecc6658356044847ffb31'",
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
