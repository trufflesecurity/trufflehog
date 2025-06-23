package langfuse

import (
	"context"
	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"testing"
)

func TestLangfuse_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: `langfuse_public_key = pk-lf-00000000-0000-0000-0000-000000000000
                    langfuse_secret_key = sk-lf-00000000-0000-0000-0000-000000000000`,
			want:  []string{"sk-lf-00000000-0000-0000-0000-000000000000"},
		},
		{
			name: "finds all matches",
			input: `langfuse_public_key1 = pk-lf-00000000-0000-0000-0000-000000000000
                    langfuse_secret_key1 = sk-lf-00000000-0000-0000-0000-000000000000
					langfuse_public_key2 = pk-lf-11111111-1111-1111-1111-111111111111
                    langfuse_secret_key2 = sk-lf-11111111-1111-1111-1111-111111111111`,
			want: []string{"sk-lf-00000000-0000-0000-0000-000000000000",
			 "sk-lf-11111111-1111-1111-1111-111111111111",
			 "sk-lf-11111111-1111-1111-1111-111111111111",
			 "sk-lf-00000000-0000-0000-0000-000000000000"},
		},
		{
			name:  "invalid pattern",
			input: `langfuse_public_key1 = pk-lf-invalid
                    langfuse_secret_key1 = sk-lf-invalid`,
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
