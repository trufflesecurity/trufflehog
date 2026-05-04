package hashicorpvaulttoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestVaultToken_PatternWithURL(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid hvs token with vault url",
			input: `
				X-Vault-Token=hvs.CAESIL37MuN9DnoD8RIri7rEi1TnNI2DCvyXNAC5X3a6qmpxGh4KHGh2cy5DR0loRzZXWm5MQlFYNmRQcFNsb1ZxYnc
				https://vault-cluster-abc123.hashicorp.cloud:8200
			`,
			want: []string{
				"hvs.CAESIL37MuN9DnoD8RIri7rEi1TnNI2DCvyXNAC5X3a6qmpxGh4KHGh2cy5DR0loRzZXWm5MQlFYNmRQcFNsb1ZxYnc:https://vault-cluster-abc123.hashicorp.cloud:8200",
			},
		},
		{
			name: "valid legacy s token with vault url",
			input: `
				s.1234567890abcdefddd
				https://vault-cluster-abc123.hashicorp.cloud:8200
			`,
			want: []string{
				"s.1234567890abcdefddd:https://vault-cluster-abc123.hashicorp.cloud:8200",
			},
		},
		{
			name: "token only, no URL",
			input: `
				hvs.abcdefghijklmnopqr
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
