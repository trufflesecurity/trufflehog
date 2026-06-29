package redhatpyxis

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestRedHatPyxis_Pattern(t *testing.T) {
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
				[INFO] redhat integration initialized
				[DEBUG] redhat_api_key=o9ynnj1wfw33a50g9009ti0ne1kqe8ac
			`,
			want: []string{
				"o9ynnj1wfw33a50g9009ti0ne1kqe8ac",
			},
		},
		{
			name: "valid pattern - multiple tokens",
			input: `
				redhat nvropikx1e0vzxpad8upkf8696icmidx
				redhatpyxis u0oxtxaurp1lbsagehya1rk6r9cxcc7f
			`,
			want: []string{
				"nvropikx1e0vzxpad8upkf8696icmidx",
				"u0oxtxaurp1lbsagehya1rk6r9cxcc7f",
			},
		},
		{
			name: "invalid pattern - uppercase characters",
			input: `
				redhat O9YNNJ1WFW33A50G9009TI0NE1KQE8AC
			`,
			want: nil,
		},
		{
			name: "invalid pattern - too short",
			input: `
				redhat abc123
			`,
			want: nil,
		},
		{
			name: "invalid pattern - too long",
			input: `
				redhat o9ynnj1wfw33a50g9009ti0ne1kqe8acabc
			`,
			want: nil,
		},
		{
			name: "invalid pattern - no keyword nearby",
			input: `
				o9ynnj1wfw33a50g9009ti0ne1kqe8ac
			`,
			want: nil,
		},
		{
			name: "invalid pattern - keyword only",
			input: `
				redhat api key configured
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))

			if len(test.want) > 0 && len(matchedDetectors) == 0 {
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
