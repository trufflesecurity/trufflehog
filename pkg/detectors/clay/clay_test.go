package clay

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestClay_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	const validToken1 = "sk_clay_5947DoiSFhtsgUwN3AcnXWjK8zabQHKSHBRHpuNKVjz3oCcpyDI"
	const validToken2 = "cly_Yv3DoiSFhtsgUwN3AcnXWjK8zabQHKSHBRHpuNKVjz3oCcpyDIdXRm"
	const validToken3 = "9f8e7d6c5b4a39281706f5e4d3c2b1a0998877665544332211aabbcc"

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "screaming snake env",
			input: `
# .env
CLAY_API_KEY=` + validToken1 + `
NEXT_PUBLIC_OTHER=foo
`,
			want: []string{validToken1},
		},
		{
			name: "snake case yaml",
			input: `
clay:
  api_key: "` + validToken1 + `"
  region: us-east-1
`,
			want: []string{validToken1},
		},
		{
			name: "camel case typescript",
			input: `
const config = {
  clayApiKey: "` + validToken2 + `",
  baseURL: "https://api.clay.com",
};
`,
			want: []string{validToken2},
		},
		{
			name: "kebab case header",
			input: `
curl -H "x-clay-key: ` + validToken3 + `" https://api.clay.com/v1/tables
`,
			want: []string{validToken3},
		},
		{
			name: "json nested",
			input: `
{
  "clay": {
    "apiKey": "` + validToken1 + `"
  }
}
`,
			want: []string{validToken1},
		},
		{
			name: "python dict",
			input: `
clay_key = "` + validToken2 + `"
client = ClayClient(clay_key)
`,
			want: []string{validToken2},
		},
		{
			name: "duplicate dedup",
			input: `
CLAY_TOKEN=` + validToken1 + `
clay_api_key: ` + validToken1 + `
`,
			want: []string{validToken1},
		},
		{
			name: "no clay keyword nearby",
			input: `
SOME_GENERIC_TOKEN=` + validToken1 + `
random text without the brand name appearing in the same line block.
`,
			want: nil,
		},
		{
			name: "placeholder rejected",
			input: `
CLAY_API_KEY=your_clay_api_key_here_replace_me
`,
			want: nil,
		},
		{
			name: "low entropy rejected",
			input: `
clay_api_key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`,
			want: nil,
		},
		{
			name: "too short rejected",
			input: `
clay_api_key: abc123
`,
			want: nil,
		},
		{
			name: "prose only",
			input: `
We use clay for outbound enrichment and route results to Salesforce.
The clay platform integrates with HubSpot natively.
`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && len(test.want) > 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d (results: %+v)", len(test.want), len(results), results)
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
