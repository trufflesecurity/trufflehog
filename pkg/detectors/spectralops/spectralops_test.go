package spectralops

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestSpectralOps_Pattern(t *testing.T) {
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
				[INFO] Running spectral scan
				[DEBUG] Using token spu-3f10194ca38240ddb880bab79492384b
				[INFO] Scan complete
			`,
			want: []string{
				"spu-3f10194ca38240ddb880bab79492384b",
			},
		},
		{
			name: "valid pattern - with keyword spectral nearby",
			input: `
				[INFO] spectral initialized
				[DEBUG] SPECTRAL_API_KEY=spu-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
			`,
			want: []string{
				"spu-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
		{
			name: "valid pattern - multiple tokens",
			input: `
				spu-11111111111111111111111111111111
				spu-22222222222222222222222222222222
			`,
			want: []string{
				"spu-11111111111111111111111111111111",
				"spu-22222222222222222222222222222222",
			},
		},
		{
			name: "invalid pattern - uppercase characters",
			input: `
				[DEBUG] token=spu-3F10194CA38240DDB880BAB79492384B
			`,
			want: nil,
		},
		{
			name: "invalid pattern - too short",
			input: `
				[DEBUG] token=spu-1234
			`,
			want: nil,
		},
		{
			name: "invalid pattern - invalid token length",
			input: `
				[DEBUG] token=spu-3f10194ca38240ddb880bab79492384badwad
			`,
			want: nil,
		},
		{
			name: "invalid pattern - keyword only",
			input: `
				[INFO] spectral scan started
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
