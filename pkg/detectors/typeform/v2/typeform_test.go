package typeform

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestTypeformV2_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern (v2)",
			input: "typeform_token = 'tfp_ABCDEfghijKLMNOPqrstuvWXYZ0123456789ABCDEFGH_ijK12340qqqBBB'",
			want:  []string{"tfp_ABCDEfghijKLMNOPqrstuvWXYZ0123456789ABCDEFGH_ijK12340qqqBBB"},
		},
		{
			name: "finds all matches (v2)",
			input: `typeform_token1 = 'tfp_ABCDEfghijKLMNOPqrstuvWXYZ0123456789ABCDEFGH_ijK12340qqqBBB'
typeform_token2 = 'tfp_943af478d3ff3d4d760020c11af102b79c440513'`,
			want: []string{"tfp_ABCDEfghijKLMNOPqrstuvWXYZ0123456789ABCDEFGH_ijK12340qqqBBB", "tfp_943af478d3ff3d4d760020c11af102b79c440513"},
		},
		{
			name:  "invalid pattern",
			input: "typeform_token = 'tfp_1'",
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
