package pganalyzereadkey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestPgAnalyzeReadKey_Pattern(t *testing.T) {
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
				[INFO] pganalyze initialized
				[DEBUG] token=pgar_abcdefghijklmnopqrstuvwxyz1
				[INFO] done
			`,
			want: []string{
				"pgar_abcdefghijklmnopqrstuvwxyz1",
			},
		},
		{
			name: "valid pattern - env variable",
			input: `
				PGANALYZE_READ_KEY=pgar_123456789012345678901234567
			`,
			want: []string{
				"pgar_123456789012345678901234567",
			},
		},
		{
			name: "valid pattern - multiple tokens",
			input: `
				pgar_aaaaaaaaaaaaaaaaaaaaaaaaaaa
				pgar_bbbbbbbbbbbbbbbbbbbbbbbbbbb
			`,
			want: []string{
				"pgar_aaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"pgar_bbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		{
			name: "invalid pattern - uppercase prefix",
			input: `
				PGAR_abcdefghijklmnopqrstuvwxyz1
			`,
			want: nil,
		},
		{
			name: "invalid pattern - too short",
			input: `
				pgar_12345
			`,
			want: nil,
		},
		{
			name: "invalid pattern - too long",
			input: `
				pgar_abcdefghijklmnopqrstuvwxyz123456
			`,
			want: nil,
		},
		{
			name: "invalid pattern - invalid characters",
			input: `
				pgar_abcde!ghijklmnopqrstuvwxyz12
			`,
			want: nil,
		},
		{
			name: "invalid pattern - keyword only",
			input: `
				pgar_
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

			results, err := d.FromData(
				context.Background(),
				false,
				[]byte(test.input),
			)
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
