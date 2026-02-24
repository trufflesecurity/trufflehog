package duo

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestDuo_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - auth api credentials",
			input: `
				[INFO] Initializing Duo Auth API
				[DEBUG] DUO_API_HOST=api-123456.duosecurity.com
				[DEBUG] DUO_IKEY=DIXXXXXXXXXXXXXXXXXX
				[DEBUG] DUO_SKEY=CWZZCIOF2aEHdx2PfexiNC3Bedai2axLMC3C2IFe
			`,
			want: []string{
				"api-123456.duosecurity.com:DIXXXXXXXXXXXXXXXXXX:CWZZCIOF2aEHdx2PfexiNC3Bedai2axLMC3C2IFe",
			},
		},
		{
			name: "valid pattern - admin api credentials",
			input: `
				[INFO] Connecting to Duo Admin API
				[DEBUG] duo_host=api-abcdef.duosecurity.com
				[DEBUG] duo_integration_key=DIYYYYYYYYYYYYYYYYYY
				[DEBUG] duo_secret_key=CWZZCIOF2aEHdx2PfexiNC3Bedai2axLMC3C2IFe
			`,
			want: []string{
				"api-abcdef.duosecurity.com:DIYYYYYYYYYYYYYYYYYY:CWZZCIOF2aEHdx2PfexiNC3Bedai2axLMC3C2IFe",
			},
		},
		{
			name: "valid pattern - json config",
			input: `
				{
					"duo": {
						"host": "api-zzzzzz.duosecurity.com",
						"ikey": "DIABCDEFGHIJKLMNOPQR",
						"duo_skey": "CWZZCIOF2aEHdx2PfexiNC3Bedai2axLMC3C2IFe"
					}
				}
			`,
			want: []string{
				"api-zzzzzz.duosecurity.com:DIABCDEFGHIJKLMNOPQR:CWZZCIOF2aEHdx2PfexiNC3Bedai2axLMC3C2IFe",
			},
		},
		{
			name: "invalid pattern - only ikey",
			input: `
				[DEBUG] DUO_IKEY=DIXXXXXXXXXXXXXXXXXX
			`,
			want: nil,
		},
		{
			name: "invalid pattern - only skey",
			input: `
				[DEBUG] DUO_SKEY=CWZZCIOF2aEHdx2PfexiNC3Bedai2axLMC3C2IFe
			`,
			want: nil,
		},
		{
			name: "invalid pattern - only host",
			input: `
				[DEBUG] DUO_API_HOST=api-123456.duosecurity.com
			`,
			want: nil,
		},
		{
			name: "invalid pattern - missing host",
			input: `
				[DEBUG] DUO_IKEY=DIXXXXXXXXXXXXXXXXXX
				[DEBUG] DUO_SKEY=CWZZCIOF2aEHdx2PfexiNC3Bedai2axLMC3C2IFe
			`,
			want: nil,
		},
		{
			name: "invalid pattern - short ikey",
			input: `
				[DEBUG] DUO_API_HOST=api-123456.duosecurity.com
				[DEBUG] DUO_IKEY=DI123
				[DEBUG] DUO_SKEY=CWZZCIOF2aEHdx2PfexiNC3Bedai2axLMC3C2IFe
			`,
			want: nil,
		},
		{
			name: "invalid pattern - short skey",
			input: `
				[DEBUG] DUO_API_HOST=api-123456.duosecurity.com
				[DEBUG] DUO_IKEY=DIXXXXXXXXXXXXXXXXXX
				[DEBUG] DUO_SKEY=deadbeef
			`,
			want: nil,
		},
		{
			name: "invalid pattern - wrong host domain",
			input: `
				[DEBUG] DUO_API_HOST=duo.example.com
				[DEBUG] DUO_IKEY=DIXXXXXXXXXXXXXXXXXX
				[DEBUG] DUO_SKEY=CWZZCIOF2aEHdx2PfexiNC3Bedai2axLMC3C2IFe
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				if len(test.want) > 0 {
					t.Errorf(
						"test %q failed: expected keywords %v to be found",
						test.name,
						d.Keywords(),
					)
				}
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)
			if len(results) != len(test.want) {
				t.Fatalf(
					"mismatch in result count: expected %d, got %d",
					len(test.want),
					len(results),
				)
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
