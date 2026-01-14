package mercadopago

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestMercadopago_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
				[INFO] Sending request to the mercadopago API
				[DEBUG] Using Key=APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
				[INFO] Response received: 200 OK
			`,
			want: []string{"APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"},
		},
		{
			name: "finds all matches",
			input: `
				[INFO] Sending request to the mercadopago API
				[DEBUG] Using Key=APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d4
				[ERROR] Response received 401 UnAuthorized
				[DEBUG] Using mercadopago Key=APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
				[INFO] Response received: 200 OK
			`,
			want: []string{"APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d4", "APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the mercadopago API
				[DEBUG] Using Key=APP_USR-0123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__-987654321
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
