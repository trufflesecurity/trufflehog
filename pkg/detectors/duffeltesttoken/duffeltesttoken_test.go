package duffeltesttoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestDuffelTestToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - basic",
			input: `
				[INFO] Starting duffel integration
				[DEBUG] Using token duffel_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
				[INFO] Complete
			`,
			want: []string{
				"duffel_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
		{
			name: "valid pattern - environment variable",
			input: `
				DUFFEL_API_TOKEN=duffel_test_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
			`,
			want: []string{
				"duffel_test_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		{
			name: "valid pattern - multiple tokens",
			input: `
				duffel_test_ccccccccccccccccccccccccccccccccccccccccccc
				duffel_test_ddddddddddddddddddddddddddddddddddddddddddd
			`,
			want: []string{
				"duffel_test_ccccccccccccccccccccccccccccccccccccccccccc",
				"duffel_test_ddddddddddddddddddddddddddddddddddddddddddd",
			},
		},
		{
			name: "invalid pattern - too short",
			input: `
				token=duffel_test_abc123
			`,
			want: nil,
		},
		{
			name: "invalid pattern - invalid characters",
			input: `
				duffel_test_aaaaaaaaaaaaaaaaaaaaaaa!aaaaaaaaaaaaaaaaaaa
			`,
			want: nil,
		},
		{
			name: "invalid pattern - keyword only",
			input: `
				Testing duffel_test_ token detection
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf(
					"test %q failed: expected keywords %v to be found in the input",
					test.name,
					d.Keywords(),
				)
				return
			}

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
