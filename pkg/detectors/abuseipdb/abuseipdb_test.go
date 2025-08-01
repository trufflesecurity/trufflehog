package abuseipdb

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAbuseipdb_Pattern(t *testing.T) {
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
				[INFO] Sending request to abuseipdb API
				[DEBUG] Using API_KEY=o8oqti3tghu2xic76ii4t7jb9bxuzd4200j1yrkdjl6s8834hx4dgz1wwo90diqraakjd13sljcjkfnf
				[INFO] Response received: 200 OK
			`,
			want: []string{"o8oqti3tghu2xic76ii4t7jb9bxuzd4200j1yrkdjl6s8834hx4dgz1wwo90diqraakjd13sljcjkfnf"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{abuseipdb}</id>
  					<secret>{abuseipdb AQAAABAAA zgtj0q3v38u4pthc6nmy02n60bj244u5o9j47ln1jlue5mxzaasfi29x4dzcbxroawvkm26thtr61066}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"zgtj0q3v38u4pthc6nmy02n60bj244u5o9j47ln1jlue5mxzaasfi29x4dzcbxroawvkm26thtr61066"},
		},
		{
			name: "valid pattern - out of prefix range",
			input: `
				[INFO] Sending request to abuseipdb API
				[INFO] Processing request
				[Info] Response received: 200 OK
				[DEBUG] Used API_KEY=o8oqti3tghu2xic76ii4t7jb9bxuzd4200j1yrkdjl6s8834hx4dgz1wwo90diqraakjd13sljcjkfnf
			`,
			want: nil,
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to abuseipdb API
				[DEBUG] Using API_KEY=7e4abcdef456Ghijkl789mnopqr012stuvwx3455123abcdef456ghijkl789mnopqr012stuvwX
				[ERROR] Response received: 400 BadRequest
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
