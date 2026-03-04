package octopusdeploy

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestOctopusDeploy_Pattern(t *testing.T) {
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
				Server: https://acme.octopus.app
				API key: API-1234567890ABCDEFGHIJKLMNO1234
			`,
			want: []string{
				"acme.octopus.app:API-1234567890ABCDEFGHIJKLMNO1234",
			},
		},
		{
			name: "valid pattern - keyword nearby",
			input: `
				OCTOPUS_URL=prod.octopus.app
				OCTOPUS_API_KEY=API-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA
			`,
			want: []string{
				"prod.octopus.app:API-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
		},
		{
			name: "valid pattern - multiple tokens",
			input: `
				dev.octopus.app
				API-11111111111111111111111111111
				API-22222222222222222222222222222
			`,
			want: []string{
				"dev.octopus.app:API-11111111111111111111111111111",
				"dev.octopus.app:API-22222222222222222222222222222",
			},
		},
		{
			name: "valid pattern - multiple urls and tokens",
			input: `
				acme.octopus.app
				prod.octopus.app
				API-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA
			`,
			want: []string{
				"acme.octopus.app:API-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"prod.octopus.app:API-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
		},
		{
			name: "invalid pattern - lowercase token",
			input: `
				acme.octopus.app
				API-abcdefghijklmnopqrstuvwxyz1234
			`,
			want: nil,
		},
		{
			name: "invalid pattern - too short",
			input: `
				acme.octopus.app
				API-1234
			`,
			want: nil,
		},
		{
			name: "invalid pattern - too long",
			input: `
				acme.octopus.app
				API-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
			`,
			want: nil,
		},
		{
			name: "invalid pattern - url only",
			input: `
				acme.octopus.app
			`,
			want: nil,
		},
		{
			name: "invalid pattern - token only",
			input: `
				API-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA
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
				actual[string(r.RawV2)] = struct{}{}
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
