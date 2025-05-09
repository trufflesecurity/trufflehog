package azureappconfigconnectionstring

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = `Endpoint=https://trufflesecurity.azconfig.io;Id=u+De;Secret=80DtxZkndXpM2mV2J1JjX2vL1x4gm1hHn8Y3JeFJ4N0PPLSO5D70JQQJ99BBAC1i4FpQkb5wAAACAAZC26dr`
	invalidPattern = `Endpoint=https://trufflesecurity.azconfig.io;Secret=80DtxZkndXpMTmV2J3JjX2vL1x4gm1hHn8Y3KeFV4N0PPLSO5D70JQQJ79BBAC1i4FpRkb5wAAACAAZC26dr`
)

func TestAzureAppConfigConnectionString_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: validPattern,
			want:  []string{"Endpoint=https://trufflesecurity.azconfig.io;Id=u+De;Secret=80DtxZkndXpM2mV2J1JjX2vL1x4gm1hHn8Y3JeFJ4N0PPLSO5D70JQQJ99BBAC1i4FpQkb5wAAACAAZC26dr"},
		},
		{
			name:  "invalid pattern",
			input: invalidPattern,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
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
