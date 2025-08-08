package bitbucketapppassword

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestBitbucketAppPassword_FromData(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pair",
			input: `
				[INFO] Sending request to the bitbucket API
				[DEBUG] Using autodesk Key=myuser:ATBB123abcDEF456ghiJKL789mnoPQR
				[INFO] Response received: 200 OK
			`,
			want: []string{"myuser:ATBB123abcDEF456ghiJKL789mnoPQR"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{}</id>
  					<secret>{AQAAABAAA https://trufflesec:ATBBa9iO-tyg7u_op@bitbucket.org}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"trufflesec:ATBBa9iO-tyg7u_op"},
		},
		{
			name:  "valid app password by itself (should not be found)",
			input: "ATBB123abcDEF456ghiJKL789mnoPQR",
			want:  []string{},
		},
		{
			name:  "pair with invalid username",
			input: "my-very-long-username-that-is-over-thirty-characters:ATBB123abcDEF456ghiJKL789mnoPQR",
			want:  []string{},
		},
		{
			name:  "url pattern",
			input: `https://anotheruser:ATBB123abcDEF456ghiJKL789mnoPQR@bitbucket.org`,
			want:  []string{"anotheruser:ATBB123abcDEF456ghiJKL789mnoPQR"},
		},
		{
			name:  "http basic auth pattern",
			input: `("basicauthuser", "ATBB123abcDEF456ghiJKL789mnoPQR")`,
			want:  []string{"basicauthuser:ATBB123abcDEF456ghiJKL789mnoPQR"},
		},
		{
			name:  "multiple matches",
			input: `user1:ATBB123abcDEF456ghiJKL789mnoPQR and then also user2:ATBBzyxwvUT987srqPON654mlkJIH`,
			want:  []string{"user1:ATBB123abcDEF456ghiJKL789mnoPQR", "user2:ATBBzyxwvUT987srqPON654mlkJIH"},
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
