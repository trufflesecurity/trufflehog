package waveapps

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestWaveApps_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - sn token in env var",
			input: `WAVE_SN_PAYMENT_TOKEN=wave_sn_prod_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345`,
			want:  []string{"wave_sn_prod_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"},
		},
		{
			name:  "valid pattern - ci token in env var",
			input: `WAVE_CI_PAYMENT_TOKEN=wave_ci_prod_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345`,
			want:  []string{"wave_ci_prod_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"},
		},
		{
			name:  "valid pattern - sn token in config",
			input: `wave_token: "wave_sn_prod_xYz123AbC456dEf789GhI012JkL345mNo"`,
			want:  []string{"wave_sn_prod_xYz123AbC456dEf789GhI012JkL345mNo"},
		},
		{
			name:  "valid pattern - ci token with dashes",
			input: `export WAVE_KEY=wave_ci_prod_abc-def-ghi-jkl-mno-pqr-stu-vwx`,
			want:  []string{"wave_ci_prod_abc-def-ghi-jkl-mno-pqr-stu-vwx"},
		},
		{
			name:  "invalid pattern - wrong prefix",
			input: `WAVE_TOKEN=wave_xx_prod_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345`,
			want:  nil,
		},
		{
			name:  "invalid pattern - too short",
			input: `WAVE_TOKEN=wave_sn_prod_tooshort`,
			want:  nil,
		},
		{
			name:  "invalid pattern - not prod",
			input: `WAVE_TOKEN=wave_sn_test_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				if len(test.want) == 0 {
					return
				}
				t.Errorf("keywords %v not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
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
