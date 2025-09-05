package makemcptoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestMakemcptoken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: "make_mcp_endpoint = 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231888/sse'",
			want:  []string{"https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231888/sse"},
		},
		{
			name: "finds all matches",
			input: `make_mcp_endpoint1 = 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231888/sse'
make_mcp_endpoint2 = 'https://eu1.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231889/sse'`,
			want: []string{"https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231888/sse", "https://eu1.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231889/sse"},
		},
		{
			name:  "invalid pattern",
			input: "make_mcp_endpoint = 'https://us2.make.com/mcp/api/v1/u/3b142ebf-e958-4aef-8551-befb27231888/foobar'",
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
