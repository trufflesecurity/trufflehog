package photoroom

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestPhotoroom_Pattern(t *testing.T) {
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
				[INFO] Sending request to the photoroom API
				[DEBUG] Using Key=sk_pr_mykey_fa02df705055df9e4d159fe3bad0cf3bb8cd1dc2
				[INFO] Response received: 200 OK
			`,
			want: []string{"sk_pr_mykey_fa02df705055df9e4d159fe3bad0cf3bb8cd1dc2"},
		},
		{
			name: "valid sandbox pattern",
			input: `
				[INFO] Sending request to the photoroom API
				[DEBUG] Using Key=sandbox_sk_pr_mykey_fa02df705055df9e4d159fe3bad0cf3bb8cd1dc2
				[INFO] Response received: 200 OK
			`,
			want: []string{"sk_pr_mykey_fa02df705055df9e4d159fe3bad0cf3bb8cd1dc2"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
					<scope>GLOBAL</scope>
					<id>{photoroom}</id>
					<secret>{photoroom AQAAABAAA sk_pr_mykey_fa02df705055df9e4d159fe3bad0cf3bb8cd1dc2}</secret>
					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"sk_pr_mykey_fa02df705055df9e4d159fe3bad0cf3bb8cd1dc2"},
		},
		{
			name: "finds all matches",
			input: `
				[INFO] Sending request to the photoroom API
				[DEBUG] Using Key=sk_pr_mykey_fa02df705055df9e4d159fe3bad0cf3bb8cd1dc2
				[ERROR] Response received 401 UnAuthorized
				[DEBUG] Using photoroom Key=sk_pr_mykey2_509b8c07454aca248a0a381b46e07f467b84c77d
				[INFO] Response received: 200 OK
			`,
			want: []string{"sk_pr_mykey_fa02df705055df9e4d159fe3bad0cf3bb8cd1dc2", "sk_pr_mykey2_509b8c07454aca248a0a381b46e07f467b84c77d"},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the photoroom API
				[DEBUG] Using Key=sk_pr_my_key_fa02df705055df9e4d159fe3bad0cf3bb8cd1dc2
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
