package auth0oauth

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAuth0oAuth_Pattern(t *testing.T) {
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
				# do not share these credentials
				auth0_credentials file: 
					auth0_clientID: kYWr_tL4eYBtqIIvKfSf2-e4T9Cw1CtwE8ufoESVBB7Hi1U
					secret: rXwGtKCleBsaUfpchggQEAy_yhzWnqv4_GzJivBif85bqiJi3ZA63DAauoJ2PF27fvS-MBqIYgxH0vZaL1s5314lgPDLqHXjZsY59PSew63A_L6rySqcy5J3rFcGcpdeSQ_tTx1kCXOZY_JUy 
					domain: 9-KhTIdSopSaMQ2v1YxdFEJN-HNgt7Mn7E8xkfQNqd51AzSGQu2yRaFauth0.com
				`,
			want: []string{"kYWr_tL4eYBtqIIvKfSf2-e4T9Cw1CtwE8ufoESVBB7Hi1UrXwGtKCleBsaUfpchggQEAy_yhzWnqv4_GzJivBif85bqiJi3ZA63DAauoJ2PF27fvS-MBqIYgxH0vZaL1s5314lgPDLqHXjZsY59PSew63A_L6rySqcy5J3rFcGcpdeSQ_tTx1kCXOZY_JUy"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{auth0 rP_yIAV6HD3Oe4zr6KawRXGbq6UCWbeC1kbjQkVhqG4vcLCc2}</id>
  					<secret>{AQAAABAAA 1PMNVllg_WHl2OGdPLSs73Z1NHjQ85nafV2qqKbQivoqEz4RSo6MFBoNxF-XqFKjEyt6WJfZvAslDPrwY-B-MLsN13rgxRrAiFw9d8Rl1e0uC0FCNDC5EALR9kq7cs4Atz_Dv4r5YT8drkV1_T5HMjH8SJb2B-jD}</secret>
  					<domain>{kXFuauth0.com}</domain>
					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"rP_yIAV6HD3Oe4zr6KawRXGbq6UCWbeC1kbjQkVhqG4vcLCc21PMNVllg_WHl2OGdPLSs73Z1NHjQ85nafV2qqKbQivoqEz4RSo6MFBoNxF-XqFKjEyt6WJfZvAslDPrwY-B-MLsN13rgxRrAiFw9d8Rl1e0uC0FCNDC5EALR9kq7cs4Atz_Dv4r5YT8drkV1_T5HMjH8SJb2B-jD"},
		},
		{
			name: "invalid pattern",
			input: `
				# do not share these credentials
				auth0_credentials file: 
					auth0_clientID: e4T9Cw1CtwE8ufoESVBB7Hi1U-e4T9Cw1CtwE8ufoESVBB7Hi1U
					secret: MBqIYgxH0vZaL1s5314lgPDLqHX^ZsY59PSew63A_L6rySqcy5J3rFcGcpdeSQ_+tTx1kCXOZY_JUy-rXwGtKCleBsaUfpchggQEAy_yhzWnqv4_GzJivBif85bqiJi3ZA63DAauoJ2PF27fvS 
					domain: 9-KhTIdSopSaMQ2v1YxdFEJN#qd51AzSGQu2yRaFauth1.com
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
