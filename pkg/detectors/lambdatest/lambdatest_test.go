package lambdatest

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestLambdatest_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	const (
		key1     = "LT_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjK"
		key2     = "LT_zyxwvutsrqponmlkjihgfedcba9876543210zyxwvutsrq0"
		user1    = "trufflesecurity"
		user2    = "truffle.user"
		key1user = key1 + user1
	)

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - env style",
			input: `
				# LambdaTest credentials for the CI runner
				LAMBDATEST_USERNAME=trufflesecurity
				LAMBDATEST_ACCESS_KEY=LT_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjK
			`,
			want: []string{key1user},
		},
		{
			name: "valid pattern - json config",
			input: `
				{
					"lambdatest": {
						"username": "truffle.user",
						"accessKey": "LT_zyxwvutsrqponmlkjihgfedcba9876543210zyxwvutsrq0"
					}
				}
			`,
			want: []string{key2 + user2},
		},
		{
			name: "finds all key-username pairs",
			input: `
				LT_AUTHKEY=LT_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjK
				LT_USERNAME=trufflesecurity
				LT_AUTHKEY=LT_zyxwvutsrqponmlkjihgfedcba9876543210zyxwvutsrq0
				LT_USERNAME=truffle.user
			`,
			want: []string{
				key1 + user1,
				key1 + user2,
				key2 + user1,
				key2 + user2,
			},
		},
		{
			name: "invalid pattern - key too short",
			input: `
				[INFO] Sending request to the lambdatest API
				LAMBDATEST_ACCESS_KEY=LT_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIj
			`,
			want: []string{},
		},
		{
			name: "invalid pattern - key in prose without a username",
			input: `
				[INFO] Sending request to the lambdatest API
				const token = "LT_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjK";
			`,
			want: []string{},
		},
		{
			name: "invalid pattern - key without a username",
			input: `
				LT_AUTHKEY is configured in the vault; export LAMBDATEST_ACCESS_KEY=LT_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjK
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
