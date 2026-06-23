package duoapisecretkey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestDuoapisecretkey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid duo secret key pattern",
			input: `
				[INFO] Configuring Duo Security
				[DEBUG] Using duo_secret_key=abcdef1234567890abcdef1234567890abcdef12
				[INFO] Integration configured successfully
			`,
			want: []string{"abcdef1234567890abcdef1234567890abcdef12"},
		},
		{
			name: "valid pattern with integration key and host",
			input: `
				duo_integration_key = DIABC123456789012345
				duo_secret_key = 1234567890abcdef1234567890abcdef12345678
				duo_api_host = api-12345678.duosecurity.com
			`,
			want: []string{"1234567890abcdef1234567890abcdef12345678"},
		},
		{
			name: "finds duo secret in config file",
			input: `
				[duo]
				integration_key = DIABC123456789012345
				secret_key = abcd1234567890abcd1234567890abcd12345678
				api_hostname = api-abcd1234.duosecurity.com
			`,
			want: []string{"abcd1234567890abcd1234567890abcd12345678"},
		},
		{
			name: "invalid pattern - too short",
			input: `
				[INFO] duo_secret_key=abcdef123456789
				[ERROR] Invalid secret key length
			`,
			want: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
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
