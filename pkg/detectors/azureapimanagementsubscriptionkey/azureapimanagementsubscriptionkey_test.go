package azureapimanagementsubscriptionkey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAzureAPIManagementSubscriptionKey_Pattern(t *testing.T) {
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
				AZURE_API_MANAGEMENT_GATEWAY_URL=https://trufflesecuritytest.azure-api.net
				AZURE_API_MANAGEMENT_SUBSCRIPTION_KEY=2c69j0dc327c4929b74d3a832a04266b
			`,
			want: []string{"https://trufflesecuritytest.azure-api.net:2c69j0dc327c4929b74d3a832a04266b"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{https://dffe5e2teoezcct050ch-2au74tmls8jm1p.azure-api.net}</id>
  					<secret>{AQAAABAAA uEDFd7-zSeH6dwwzLbGjVrAlfgXoV1Xv}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"https://dffe5e2teoezcct050ch-2au74tmls8jm1p.azure-api.net:uEDFd7-zSeH6dwwzLbGjVrAlfgXoV1Xv"},
		},
		{
			name: "invalid pattern",
			input: `
				AZURE_API_MANAGEMENT_GATEWAY_URL=https://trufflesecuritytest.azure-api.net
				AZURE_API_MANAGEMENT_SUBSCRIPTION_KEY=2c69j2dc3f7c4929b74d3a832a042
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
