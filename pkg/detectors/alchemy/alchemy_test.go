package alchemy

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAlchemy_Pattern(t *testing.T) {
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
				[INFO] Sending request to the alchemy API
				[DEBUG] Using Key=alcht_2Cy8xCLyvrAf7lZKfhQhyCr4RAID9D
				[INFO] Response received: 200 OK
			`,
			want: []string{"alcht_2Cy8xCLyvrAf7lZKfhQhyCr4RAID9D"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{alchemy}</id>
  					<secret>{alchemy AQAAABAAA 5iqW7gKQVXvwnykF9xAVfenemmnUJznI}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"5iqW7gKQVXvwnykF9xAVfenemmnUJznI"},
		},
		{
			name: "finds all matches",
			input: `
				[INFO] Sending request to the alchemy API
				[DEBUG] Using Key=alcht_2Cy8xCLyvrAf7lZKfhQhyCr4RAID9D
				[ERROR] Response received 401 UnAuthorized
				[DEBUG] Using alchemy Key=xuQIeWFVEp8k8Uu9FwPx6X5C8IViOe1o
				[INFO] Response received: 200 OK
			`,
			want: []string{"alcht_2Cy8xCLyvrAf7lZKfhQhyCr4RAID9D", "xuQIeWFVEp8k8Uu9FwPx6X5C8IViOe1o"},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the alchemy API
				[DEBUG] Using Key=alcht_a2Cy8xCLyvrAf7lZKfhQhyCr4RAID9D
				[ERROR] Response received: 401 UnAuthorized
			`,
			want: []string{},
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
