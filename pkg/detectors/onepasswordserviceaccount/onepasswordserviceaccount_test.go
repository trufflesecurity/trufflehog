package onepasswordserviceaccount

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var validToken = "ops_eyJzaWduSW5BZGRyZXNzIjoiZXhhbXBsZS4xcGFzc3dvcmQuY29tIiwidXNlckF1dGgiOnsibWV0aG9kIjoiU1JQZy00MDk2IiwiYWxnIjoiUEJFUzJnLUhTMjU2In19"

func TestOnepasswordServiceAccount_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
				[INFO] Connecting to 1Password vault
				[DEBUG] Using token: ` + validToken + `
				[INFO] Response received: 200 OK
			`,
			want: []string{validToken},
		},
		{
			name: "invalid pattern - wrong prefix",
			input: `
				[INFO] Connecting to 1Password vault
				[DEBUG] Using token: ops_eyJ!!invalid!!notbase64content
				[ERROR] Response received: 401 Unauthorized
			`,
			want: []string{},
		},
		{
			name: "invalid pattern - too short",
			input: `
				[INFO] Connecting to 1Password vault
				[DEBUG] Using token: ops_eyJhbGciOiJSUzI1Ng
				[ERROR] Response received: 401 Unauthorized
			`,
			want: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
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
