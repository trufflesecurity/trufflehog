package azureappconfigconnectionstring

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
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
			input: `Endpoint=https://trufflesecurity.azconfig.io;Id=u+De;Secret=80DtxZkndXpM2mV2J1JjX2vL1x4gm1hHn8Y3JeFJ4N0PPLSO5D70JQQJ99BBAC1i4FpQkb5wAAACAAZC26dr`,
			want:  []string{"Endpoint=https://trufflesecurity.azconfig.io;Id=u+De;Secret=80DtxZkndXpM2mV2J1JjX2vL1x4gm1hHn8Y3JeFJ4N0PPLSO5D70JQQJ99BBAC1i4FpQkb5wAAACAAZC26dr"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{connectionstring}</id>
  					<secret>{AQAAABAAA Endpoint=https://iTHzRfnepCddRiYoBbPj-drVzUjwTNduwb3EUOTsuSAgg1e83Q7bw.azconfig.io;Id=eO04L+/m9rYn;Secret=G4jQ3GmcsYqlLkkG8uoIVbx08PZIJSdfB/7}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"Endpoint=https://iTHzRfnepCddRiYoBbPj-drVzUjwTNduwb3EUOTsuSAgg1e83Q7bw.azconfig.io;Id=eO04L+/m9rYn;Secret=G4jQ3GmcsYqlLkkG8uoIVbx08PZIJSdfB/7"},
		},
		{
			name:  "invalid pattern",
			input: `Endpoint=https://trufflesecurity.azconfig.io;Secret=80DtxZkndXpMTmV2J3JjX2vL1x4gm1hHn8Y3KeFV4N0PPLSO5D70JQQJ79BBAC1i4FpRkb5wAAACAAZC26dr`,
			want:  nil,
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
