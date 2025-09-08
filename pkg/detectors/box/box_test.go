package box

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestBox_Pattern(t *testing.T) {
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
				[INFO] request received to fetch box data
				[INFO] sending API request to box API
				[DEBUG] using Key=Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ
				[DEBUG] request sent successfully
				[INFO] response received: 200 OK
				[DEBUG] fetch data from the database for ID Qje1HjJmgrNzOQpQZROEeYjmHbD2qdFF
				[INFO] data returned
			`,
			want: []string{"Ogowv5cj5AJJjO5F3daNHbKJDdPud0CZ"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{box}</id>
  					<secret>{box AQAAABAAA Dxb2zNdFF2QTSMwrZJnoeD54Dc4zZAIW}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"Dxb2zNdFF2QTSMwrZJnoeD54Dc4zZAIW"},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] request received to fetch box data
				[INFO] sending API request to box API
				[DEBUG] using Key=Ogow-v5cj-5AJJ-jO5F-3daN-HbKJ-DdPu-d0CZ
				[DEBUG] request sent successfully
				[ERROR] response received: 401 UnAuthorized
				[INFO] nothing to return
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
