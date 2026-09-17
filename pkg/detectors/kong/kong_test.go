package kong

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestKong_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern kong kpat",
			input: "kpat_dqEmLNYmj8VqmetheiTNRZfHW1XxkGRDgd1XjCAz0I9oeKRRB",
			want:  []string{"kpat_dqEmLNYmj8VqmetheiTNRZfHW1XxkGRDgd1XjCAz0I9oeKRRB"},
		},
		{
			name:  "valid pattern kong spat",
			input: "spat_tDxgO2RWDH2nxyyfEzmiW3YLpkQsQjstT9nufCcJeKCg7CoDj",
			want:  []string{"spat_tDxgO2RWDH2nxyyfEzmiW3YLpkQsQjstT9nufCcJeKCg7CoDj"},
		},
		{
			name: "finds all matches",
			input: `
				[INFO] Sending request to the kong API
				[DEBUG] Using token=spat_tDxgO2RWDH2nxyyfEzmiW3YLpkQsQjstT9nufCcJeKCg7CoDj
				[ERROR] Response received 401 UnAuthorized
				[DEBUG] Using token=kpat_dqEmLNYmj8VqmetheiTNRZfHW1XxkGRDgd1XjCAz0I9oeKRRB
				[INFO] Response received: 200 OK
			`,
			want: []string{"spat_tDxgO2RWDH2nxyyfEzmiW3YLpkQsQjstT9nufCcJeKCg7CoDj", "kpat_dqEmLNYmj8VqmetheiTNRZfHW1XxkGRDgd1XjCAz0I9oeKRRB"},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the kong API
				[DEBUG] Using token=kpat_foo
				[DEBUG] Using token=spat_bar
				[ERROR] Response received: 401 UnAuthorized
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
