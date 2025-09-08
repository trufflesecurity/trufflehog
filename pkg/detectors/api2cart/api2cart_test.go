package api2cart

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestApi2Cart_Pattern(t *testing.T) {
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
				To integrate with API2Cart, ensure you have the following credentials in your configuration file.
				Your API2CART key is 2afddb813193eb9d3b5bd99bf5d834cd, which you will need to access the API securely. 

				The following endpoints are available for your use:
				- Get Products: https://api.api2cart.com/v1.0/products/get
				- Add Product: https://api.api2cart.com/v1.0/products/add
				`,
			want: []string{"2afddb813193eb9d3b5bd99bf5d834cd"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{api2cart}</id>
  					<secret>{AQAAABAAA b36c17e9dc0dba67480e864cf69879c3}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"b36c17e9dc0dba67480e864cf69879c3"},
		},
		{
			name: "invalid pattern",
			input: `
				To integrate with API2Cart, ensure you have the following credentials in your configuration file.
				Your API2CART key is 68d746609J4240840734c22836725d76, which you will need to access the API securely. 

				The following endpoints are available for your use:
				- Get Products: https://api.api2cart.com/v1.0/products/get
				- Add Product: https://api.api2cart.com/v1.0/products/add
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
