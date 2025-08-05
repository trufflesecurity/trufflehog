package azuredirectmanagementkey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAzureDirectManagementAPIKey_Pattern(t *testing.T) {
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
				AZURE_MANGEMENT_API_KEY=UJh1Wn7txjls2GPK1YxO9+3tpqQffSfxb+97PmT8j3cSQoXvGa74lCKpBqPeppTHCharbaMeKqKs/H4gA/go1w==
				AZURE_MANAGEMENT_API_URL=https://trufflesecuritytest.management.azure-api.net
				`,
			want: []string{"https://trufflesecuritytest.management.azure-api.net:UJh1Wn7txjls2GPK1YxO9+3tpqQffSfxb+97PmT8j3cSQoXvGa74lCKpBqPeppTHCharbaMeKqKs/H4gA/go1w=="},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{https://0q66287uqx.management.azure-api.net}</id>
  					<secret>{AQAAABAAA Ub4yMRDBBdEX/BNyNFM6i6Odj25TB0Zd1BRNx57ZeMGpqzkeokXheNpkkTBtvPQb692id65yc2xLKhZ183rg==}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"https://0q66287uqx.management.azure-api.net:Ub4yMRDBBdEX/BNyNFM6i6Odj25TB0Zd1BRNx57ZeMGpqzkeokXheNpkkTBtvPQb692id65yc2xLKhZ183rg=="},
		},
		{
			name: "invalid pattern",
			input: `
				AZURE_MANGEMENT_API_KEY=UJh1Wn7txjls2GPK1YxO9+3tpqQffSfxb+97PmT8j3cSQoXvGa74lCKp
				AZURE_MANAGEMENT_API_URL=https://trufflesecuritytest.management.azure-api.net
				`,
			want: nil,
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
