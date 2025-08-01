package ambee

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAmbee_Pattern(t *testing.T) {
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
				[INFO] Sending request to the ambee API
				[DEBUG] Using Key=eccb41cc2d4dab96b748ed040e9b308161279820447ef4553ba6e6d20ecb9962
				[INFO] Response received: 200 OK
			`,
			want: []string{"eccb41cc2d4dab96b748ed040e9b308161279820447ef4553ba6e6d20ecb9962"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{ambee}</id>
  					<secret>{ambee AQAAABAAA b91280c63e1571ad928d52947cc31a14ad1bf5a83088d0346b94f6683cf22138}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"b91280c63e1571ad928d52947cc31a14ad1bf5a83088d0346b94f6683cf22138"},
		},
		{
			name: "valid pattern - key out of prefix range",
			input: `
				[INFO] Fetching data from ambee
				[INFO] Sending request to the API
				[DEBUG] Using Key=eccb41cc2d4dab96b748ed040e9b308161279820447ef4553ba6e6d20ecb9962
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the ambee API
				[DEBUG] Using Key=eccb41cc2d4dab96y748ed040e9b308161279820447ef4553ba6e6d20ecb9962
				[INFO] Response received: 200 OK
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
