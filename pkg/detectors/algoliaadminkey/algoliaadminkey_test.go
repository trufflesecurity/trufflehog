package algoliaadminkey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAlgoliaAdminKey_Pattern(t *testing.T) {
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
				[DEBUG] Using algolia Key=BsDaN7ZU7kFiUX5CpN8CUf3nkMaSeZYn
				[DEBUG] Using docsearch ID=844XQV5SUA
				[INFO] Response received: 200 OK
			`,
			want: []string{"844XQV5SUA:BsDaN7ZU7kFiUX5CpN8CUf3nkMaSeZYn"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{appId 0VJ9I1WV78}</id>
  					<secret>{algolia AQAAABAAA 4AYm3wz7nfnX7Bqtw5e5Qo3Z5vfBe0eS}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"0VJ9I1WV78:4AYm3wz7nfnX7Bqtw5e5Qo3Z5vfBe0eS"},
		},
		{
			name: "valid pattern - key out of prefix range",
			input: `
				[INFO] Sending request to the algolia API
				[DEBUG] Using Key=BsDaN7ZU7kFiUX5CpN8CUf3nkMaSeZYn
				[DEBUG] Using ID=844XQV5SUA
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the API
				[DEBUG] Using algolia Key=BsD-N7ZU7kFiUX5CpN8CUf3nkMaSeZYn
				[DEBUG] Using docsearch ID=844XqV5SUA
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
