package shippo

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestShippo_Pattern(t *testing.T) {
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
				[INFO] Starting shipment service
				[DEBUG] token=shippo_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
				[INFO] Ready
			`,
			want: []string{
				"shippo_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
		{
			name: "valid pattern - with keyword nearby",
			input: `
				[DEBUG] SHIPPO_API_KEY=shippo_live_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
			`,
			want: []string{
				"shippo_live_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		{
			name: "valid pattern - multiple tokens",
			input: `
				shippo_live_1111111111111111111111111111111111111111
				shippo_live_2222222222222222222222222222222222222222
			`,
			want: []string{
				"shippo_live_1111111111111111111111111111111111111111",
				"shippo_live_2222222222222222222222222222222222222222",
			},
		},
		{
			name: "invalid pattern - uppercase characters",
			input: `
				shippo_live_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
			`,
			want: nil,
		},
		{
			name: "invalid pattern - too short",
			input: `
				shippo_live_1234
			`,
			want: nil,
		},
		{
			name: "invalid pattern - invalid token length",
			input: `
				shippo_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
			`,
			want: nil,
		},
		{
			name: "invalid pattern - keyword only",
			input: `
				[INFO] initializing shippo service shippo_live_
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

func TestShippo_TestKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid test key - basic",
			input: `
				shippo_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
			`,
			want: []string{
				"shippo_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
		{
			name: "valid test key - with keyword nearby",
			input: `
				SHIPPO_API_KEY=shippo_test_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
			`,
			want: []string{
				"shippo_test_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		{
			name: "valid test key - multiple tokens",
			input: `
				shippo_test_1111111111111111111111111111111111111111
				shippo_test_2222222222222222222222222222222222222222
			`,
			want: []string{
				"shippo_test_1111111111111111111111111111111111111111",
				"shippo_test_2222222222222222222222222222222222222222",
			},
		},
		{
			name: "invalid test key - uppercase characters",
			input: `
				shippo_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
			`,
			want: nil,
		},
		{
			name: "invalid test key - too short",
			input: `
				shippo_test_1234
			`,
			want: nil,
		},
		{
			name: "invalid test key - invalid token length",
			input: `
				shippo_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
			`,
			want: nil,
		},
		{
			name: "invalid test key - keyword only",
			input: `
				shippo_test_
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
