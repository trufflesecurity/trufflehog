package waveapps

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestWaveapps_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - sn token",
			input: `
				[INFO] Wave payment configuration
				WAVE_SN_PAYMENT_TOKEN=wave_sn_prod_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
				[INFO] Processing payments
			`,
			want: []string{"wave_sn_prod_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"},
		},
		{
			name: "valid pattern - ci token",
			input: `
				[DEBUG] Using CI payment token
				WAVE_CI_PAYMENT_TOKEN=wave_ci_prod_x9y8w7v6u5t4s3r2q1p0o9n8m7l6k5j4
				[INFO] Token loaded
			`,
			want: []string{"wave_ci_prod_x9y8w7v6u5t4s3r2q1p0o9n8m7l6k5j4"},
		},
		{
			name: "valid pattern - in config file",
			input: `
				payment:
				  provider: waveapps
				  token: wave_sn_prod_abc123def456ghi789jkl012mno345pq
			`,
			want: []string{"wave_sn_prod_abc123def456ghi789jkl012mno345pq"},
		},
		{
			name: "invalid pattern - too short",
			input: `
				WAVE_TOKEN=wave_sn_prod_tooshort
			`,
			want: nil,
		},
		{
			name: "invalid pattern - wrong prefix",
			input: `
				TOKEN=wave_xx_prod_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				if len(test.want) == 0 {
					return
				}
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
