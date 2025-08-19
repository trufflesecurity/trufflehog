package airship

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAirship_Pattern(t *testing.T) {
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
				[INFO] Sending request to the airship API
				[DEBUG] Using Key=O3BV99CUDw3xYUAL0tHGYUe7mOj5PA5vTnLdJwULCTh9dxk9PmmTpL1kI846G3QGIsECVyVSsxZnIbfSwWc8xuX843W
				[INFO] Response received: 200 OK
			`,
			want: []string{"O3BV99CUDw3xYUAL0tHGYUe7mOj5PA5vTnLdJwULCTh9dxk9PmmTpL1kI846G3QGIsECVyVSsxZnIbfSwWc8xuX843W"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{airship}</id>
  					<secret>{airship AQAAABAAA oVH3yIO1oAoXpK9Rc01EGNNTuw6d4Zyt07YNFmje644Ht00hvAaYwldNOV9vIPQw6dYHJLRgp2f75YdJ9OiICkYVhMI}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"oVH3yIO1oAoXpK9Rc01EGNNTuw6d4Zyt07YNFmje644Ht00hvAaYwldNOV9vIPQw6dYHJLRgp2f75YdJ9OiICkYVhMI"},
		},
		{
			name: "valid pattern - key out of prefix range",
			input: `
				[DEBUG] airship api processing
				[INFO] Sending request to the API
				[DEBUG] Using Key=O3BV99CUDw3xYUAL0tHGYUe7mOj5PA5vTnLdJwULCTh9dxk9PmmTpL1kI846G3QGIsECVyVSsxZnIbfSwWc8xuX843W
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the airship API
				[DEBUG] Using Key=O3BV99CUDw3xY#AL0tHGYUe7mOj5PA5vTnLdJwULCTh9dxk9PmmTpL1kI846G3QGIsECVyVSsxZnIbfSwWc8xuX843W
				[ERROR] Response received: 401 UnAuthorized
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
