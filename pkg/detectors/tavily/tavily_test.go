package tavily

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestTavily_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - plain key",
			input: `tavily_key = "tvly-aBcDeFgHiJkLmNoPqRsT"`,
			want:  []string{"tvly-aBcDeFgHiJkLmNoPqRsT"},
		},
		{
			name:  "valid pattern - dev tier",
			input: `TAVILY_API_KEY=tvly-dev-aBcDeFgHiJkLmNoPqRsTuVwX`,
			want:  []string{"tvly-dev-aBcDeFgHiJkLmNoPqRsTuVwX"},
		},
		{
			name:  "valid pattern - prod tier",
			input: `export TAVILY_API_KEY="tvly-prod-aBcDeFgHiJkLmNoPqRsT1234"`,
			want:  []string{"tvly-prod-aBcDeFgHiJkLmNoPqRsT1234"},
		},
		{
			name: "valid pattern - multiple keys",
			input: `
				tvly-AAAAAAAAAAAAAAAAAAAAAAAA
				tvly-dev-BBBBBBBBBBBBBBBBBBBBBBBB
			`,
			want: []string{
				"tvly-AAAAAAAAAAAAAAAAAAAAAAAA",
				"tvly-dev-BBBBBBBBBBBBBBBBBBBBBBBB",
			},
		},
		{
			name:  "invalid pattern - too short",
			input: `tavily_key = "tvly-abc123"`,
			want:  nil,
		},
		{
			name:  "invalid pattern - prefix only",
			input: `TAVILY_API_KEY=tvly-`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && len(test.want) > 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
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
