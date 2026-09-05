package castai

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestCastai_Pattern(t *testing.T) {
	d := New()
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
				[INFO] Sending request to the castai API
				[DEBUG] Using castai_v1_2cb5a70064f60ba2f5507bcbb02938a5a0483bf2a9742d08c5c274c827c9f6ea_aaabbbb5
				[INFO] Response received: 200 OK
			`,
			want: []string{"castai_v1_2cb5a70064f60ba2f5507bcbb02938a5a0483bf2a9742d08c5c274c827c9f6ea_aaabbbb5"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
					<scope>GLOBAL</scope>
					<id>{castai}</id>
					<secret>{castai_v1_2cb5a70064f60ba2f5507bcbb02938a5a0483bf2a9742d08c5c274c827c9f6ea_aaabbbb5}</secret>
					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"castai_v1_2cb5a70064f60ba2f5507bcbb02938a5a0483bf2a9742d08c5c274c827c9f6ea_aaabbbb5"},
		},
		{
			name: "finds all matches",
			input: `
				[INFO] Sending request to the castai API
				[DEBUG] Using Key=castai_v1_2cb5a70064f60ba2f5507bcbb02938a5a0483bf2a9742d08c5c274c827c9f6ea_aaabbbb5
				[ERROR] Response received 401 UnAuthorized
				[DEBUG] Using castai Key=castai_v1_2cb5a70064f60ba2f5507bcbb02938a5a0483bf2a9742d08c5c274c827c9f6ea_aaabbccc
				[INFO] Response received: 200 OK
			`,
			want: []string{"castai_v1_2cb5a70064f60ba2f5507bcbb02938a5a0483bf2a9742d08c5c274c827c9f6ea_aaabbbb5", "castai_v1_2cb5a70064f60ba2f5507bcbb02938a5a0483bf2a9742d08c5c274c827c9f6ea_aaabbccc"},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the castai API
				[DEBUG] Using Key=castai_v1_2cb5a70xxxx
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
