package alibaba

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAliBaba_Pattern(t *testing.T) {
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
				[INFO] Sending request to the API
				[DEBUG] Using Key=CwgR2UwgaWd7hgUdQkwFnK9vvEeO4R
				[DEBUG] Using ID=LTAIXgRPqwF1DhBf6Q1uZ5DrM
				[INFO] Response received: 200 OK
			`,
			want: []string{"CwgR2UwgaWd7hgUdQkwFnK9vvEeO4RLTAIXgRPqwF1DhBf6Q1uZ5DrM"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{WX6OtM8pbcrXWMIGc5evYousFWBlBm}</id>
  					<secret>{AQAAABAAA LTAImg3ZeAPatbAtEDS9HVZ}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"WX6OtM8pbcrXWMIGc5evYousFWBlBmLTAImg3ZeAPatbAtEDS9HVZ"},
		},
		{
			name: "valid pattern - ignore special characters at end",
			input: `
				[INFO] Sending request to the API
				[DEBUG] Using Key=CwgR2UwgaWd7hgUdQkwFnK9vvEeO4R
				[DEBUG] Using ID=LTAIXgRPqwF1DhBf6Q1uZ5DrM;
				[INFO] Response received: 200 OK
			`,
			want: []string{"CwgR2UwgaWd7hgUdQkwFnK9vvEeO4RLTAIXgRPqwF1DhBf6Q1uZ5DrM"},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the API
				[DEBUG] Using Key=CwgR2UwgaWd7hgUdQkwFnK9vvEeO4
				[DEBUG] Using ID=LTAIXgRPqwF1DhBf6Q1uZ5DrMYPW
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
