package testmuai

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestTestMuAI_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	// Valid 50-character access key (LT_ + 47 alphanumeric) - using fake test key
	validKey := "LT_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJK"

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - environment variables",
			input: `
				export LT_USERNAME=testuser
				export LT_ACCESS_KEY=` + validKey + `
			`,
			want: []string{"testuser:" + validKey},
		},
		{
			name: "valid pattern - single line",
			input: `LT_USERNAME=qauser LT_ACCESS_KEY=LT_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJK`,
			want: []string{"qauser:LT_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJK"},
		},
		{
			name: "invalid pattern - access key too short",
			input: `
				export LT_USERNAME=testuser
				export LT_ACCESS_KEY=LT_tooshort123
			`,
			want: nil,
		},
		{
			name: "invalid pattern - missing LT_ prefix",
			input: `
				export LT_USERNAME=testuser
				export LT_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJK
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				if len(test.want) > 0 {
					t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				}
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
