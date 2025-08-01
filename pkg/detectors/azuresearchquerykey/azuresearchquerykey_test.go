package azuresearchquerykey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAzureSearchQueryKey_Pattern(t *testing.T) {
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
				azure:
					azure_url: https://tzyexx2ktdfhha8w1cktqzbrgv37ywtu.search.windows.net/indexes/n81wg81jogjfq93cyxfi67vy2g7vwlcqfgi
					azure_key: OKalbM5EBt5hloqU46phTUCZqvNAlZ4S2Jd2gFUCOQ3HG0vQ2uEp
				`,
			want: []string{"OKalbM5EBt5hloqU46phTUCZqvNAlZ4S2Jd2gFUCOQ3HG0vQ2uEphttps://tzyexx2ktdfhha8w1cktqzbrgv37ywtu.search.windows.net/indexes/n81wg81jogjfq93cyxfi67vy2g7vwlcqfgi"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{azure https://w3fsj4c22rdn7mhkf1yxbt7orrvzd720a.search.windows.net/indexes/5934qi40xctuhmzba7ty}</id>
  					<secret>{azure AQAAABAAA C3idqCYnGa1cTx7iEFJ684QCbSDcEz1jq4s7iRxDDPWYKoK3h3Lr}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"C3idqCYnGa1cTx7iEFJ684QCbSDcEz1jq4s7iRxDDPWYKoK3h3Lrhttps://w3fsj4c22rdn7mhkf1yxbt7orrvzd720a.search.windows.net/indexes/5934qi40xctuhmzba7ty"},
		},
		{
			name: "invalid pattern",
			input: `
				azure:
					url: http://invalid.azurecr.io.azure.com
					azure_key: BXIMbhBlC3=5hIbqCEKvq7op!V2ZfO0XWbcnasZmPm/AJfQqdcnt/+2Ytxc1hDq1m/
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
