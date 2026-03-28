package hashicorpbatchtoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestBatchToken_PatternWithURL(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid hvb token with vault url",
			input: `
				X-Vault-Token=hvb.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
				https://vault-cluster-abc123.hashicorp.cloud:8200
			`,
			want: []string{
				"hvb.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaahttps://vault-cluster-abc123.hashicorp.cloud:8200",
			},
		},
		{
			name: "valid hvb token with longer length",
			input: `
				hvb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
				https://vault-cluster-xyz.hashicorp.cloud
			`,
			want: []string{
				"hvb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbhttps://vault-cluster-xyz.hashicorp.cloud",
			},
		},
		{
			name: "token only, no URL",
			input: `
				hvb.cccccccccccccccccccccccccccccccccccccccccccccccccc
			`,
			want: nil,
		},
		{
			name: "URL only, no token",
			input: `
				https://vault-cluster-abc123.hashicorp.cloud:8200
			`,
			want: nil,
		},
		{
			name: "invalid token - too short",
			input: `
				hvb.shorttoken
				https://vault-cluster-abc123.hashicorp.cloud
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && len(test.want) > 0 {
				t.Errorf(
					"test %q failed: expected keywords %v to be found in the input",
					test.name,
					d.Keywords(),
				)
				return
			}

			d.UseFoundEndpoints(true)

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf(
					"mismatch in result count: expected %d, got %d",
					len(test.want),
					len(results),
				)
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
