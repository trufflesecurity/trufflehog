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
			name: "valid access token",
			input: `
				MERCADO_PAGO_ACCESS_TOKEN=APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__-987654321
			`,
			want: []string{"APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__-987654321"},
		},
		{
			name: "valid access token - BR region",
			input: `
				MP_ACCESS_TOKEN=APP_USR-9988776655443322-150623-abcdef0123456789abcdef0123456789__BR_ML__-112233445
			`,
			want: []string{"APP_USR-9988776655443322-150623-abcdef0123456789abcdef0123456789__BR_ML__-112233445"},
		},
		{
			name: "valid public key",
			input: `
				MERCADO_PAGO_PUBLIC_KEY=APP_USR-12345678-1234-1234-1234-123456789abc
			`,
			want: []string{"APP_USR-12345678-1234-1234-1234-123456789abc"},
		},
		{
			name: "valid - both access token and public key",
			input: `
				MERCADO_PAGO_ACCESS_TOKEN=APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__-987654321
				MERCADO_PAGO_PUBLIC_KEY=APP_USR-abcdef01-2345-6789-abcd-ef0123456789
			`,
			want: []string{
				"APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__-987654321",
				"APP_USR-abcdef01-2345-6789-abcd-ef0123456789",
			},
		},
		{
			name: "valid - in YAML config",
			input: `
				mercadopago:
				  access_token: "APP_USR-5555666677778888-251299-fedcba9876543210fedcba9876543210__MX_ML__-123456789"
				  environment: production
			`,
			want: []string{"APP_USR-5555666677778888-251299-fedcba9876543210fedcba9876543210__MX_ML__-123456789"},
		},
		{
			name: "valid - bearer header",
			input: `
				Authorization: Bearer APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__-987654321
			`,
			want: []string{"APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__-987654321"},
		},
		{
			name: "valid - multiple access tokens",
			input: `
				PROD_TOKEN=APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__-987654321
				STAGING_TOKEN=APP_USR-9988776655443322-150623-abcdef0123456789abcdef0123456789__BR_ML__-112233445
			`,
			want: []string{
				"APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__-987654321",
				"APP_USR-9988776655443322-150623-abcdef0123456789abcdef0123456789__BR_ML__-112233445",
			},
		},
		{
			name:  "invalid - access token hash too short",
			input: `TOKEN=APP_USR-1234567890123456-010122-a1b2c3d4__LA_LD__-987654321`,
			want:  []string{},
		},
		{
			name:  "invalid - access token missing merchant id",
			input: `TOKEN=APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__`,
			want:  []string{},
		},
		{
			name:  "invalid - public key wrong format",
			input: `TOKEN=APP_USR-not-a-valid-uuid-format-here`,
			want:  []string{},
		},
		{
			name:  "invalid - no APP_USR prefix",
			input: `TOKEN=USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__-987654321`,
			want:  []string{},
		},
		{
			name:  "invalid - user id too short",
			input: `TOKEN=APP_USR-12345678-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__-987654321`,
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && len(test.want) > 0 {
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
