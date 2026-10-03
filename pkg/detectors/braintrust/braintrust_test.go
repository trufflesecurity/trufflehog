package braintrust

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestBraintrust_Pattern(t *testing.T) {
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
				[INFO] Starting AI eval
				[DEBUG] braintrust_key=sk-JMwsKdC5JJfEGS4NhbQjzh1zfeYvGCuBkosFRWn98Z1H13Yg
			`,
			want: []string{
				"sk-JMwsKdC5JJfEGS4NhbQjzh1zfeYvGCuBkosFRWn98Z1H13Yg",
			},
		},
		{
			name: "valid pattern - with keyword nearby",
			input: `
				[INFO] braintrust initialized
				[DEBUG] BRAINTRUST_API_KEY=sk-76cnJ2Ns8wHZao70KdUdlZpBuSzej8gEokToNyeSPtd1RyZB
			`,
			want: []string{
				"sk-76cnJ2Ns8wHZao70KdUdlZpBuSzej8gEokToNyeSPtd1RyZB",
			},
		},
		{
			name: "valid pattern - multiple tokens",
			input: `
				braintrust_key1=sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				braintrust_key2=sk-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
			`,
			want: []string{
				"sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"sk-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			},
		},
		{
			name: "invalid pattern - too short",
			input: `
				[DEBUG] braintrust_key=sk-1234
			`,
			want: nil,
		},
		{
			name: "invalid pattern - too long",
			input: `
				[DEBUG] braintrust_key=sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
			`,
			want: nil,
		},
		{
			name: "invalid pattern - invalid characters",
			input: `
				[DEBUG] braintrust_key=sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
			`,
			want: nil,
		},
		{
			name: "invalid pattern - keyword only",
			input: `
				[INFO] braintrust API initialized sk-
			`,
			want: nil,
		},
		{
			name: "valid pattern - mixed alphanumeric",
			input: `
				[DEBUG] braintrust_key=sk-a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ1234567890ao
			`,
			want: []string{
				"sk-a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ1234567890ao",
			},
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
