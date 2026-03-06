package ranchertoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestRancherToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - env var",
			input: `
				export CATTLE_TOKEN=jswpl27hs8pd88rmw2mgfgrjtpljp85fd5v7rhdwr2s6z22hvt6vjt
			`,
			want: []string{"jswpl27hs8pd88rmw2mgfgrjtpljp85fd5v7rhdwr2s6z22hvt6vjt"},
		},
		{
			name: "valid pattern - yaml config",
			input: `
apiVersion: v1
kind: Pod
metadata:
  name: rancher-agent
spec:
  containers:
    - name: agent
      env:
        - name: RANCHER_TOKEN
          value: "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567a"
`,
			want: []string{"abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567a"},
		},
		{
			name: "valid pattern - terraform",
			input: `
resource "rancher2_cluster" "example" {
  # RANCHER_TOKEN is used for authentication
  token_key = "xz9yw8vt7sr6qp5on4ml3kj2ih1gf0ed9cb8az7yx6wv5ut4sr3qp0"
}
`,
			want: nil, // token_key is not one of the context keywords in the regex
		},
		{
			name: "valid pattern - terraform with context keyword",
			input: `
# Configure the Rancher provider
# RANCHER_TOKEN = "xz9yw8vt7sr6qp5on4ml3kj2ih1gf0ed9cb8az7yx6wv5ut4sr3qp0"
`,
			want: []string{"xz9yw8vt7sr6qp5on4ml3kj2ih1gf0ed9cb8az7yx6wv5ut4sr3qp0"},
		},
		{
			name: "invalid pattern - no context keyword",
			input: `
				SECRET=jswpl27hs8pd88rmw2mgfgrjtpljp85fd5v7rhdwr2s6z22hvt6vjt
			`,
			want: nil,
		},
		{
			name: "invalid pattern - too short",
			input: `
				export CATTLE_TOKEN=tooshort
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				if len(test.want) == 0 {
					return
				}
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
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
