package mercadopago

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestMercadoPago_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - access token",
			input: "mercadopago_token = APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__-987654321",
			want:  []string{"APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__-987654321"},
		},
		{
			name:  "valid pattern - in env file",
			input: "MERCADO_PAGO_ACCESS_TOKEN=APP_USR-6329847201583746-031522-f0e1d2c3b4a5968778695a4b3c2d1e0f__LA_LD__-123456789",
			want:  []string{"APP_USR-6329847201583746-031522-f0e1d2c3b4a5968778695a4b3c2d1e0f__LA_LD__-123456789"},
		},
		{
			name:  "invalid pattern - public key format",
			input: "APP_USR-12345678-1234-1234-1234-123456789abc",
			want:  nil,
		},
		{
			name:  "invalid pattern - no prefix",
			input: "some_random_token_value_that_does_not_match",
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
