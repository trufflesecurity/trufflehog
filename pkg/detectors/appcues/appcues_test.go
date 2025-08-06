package appcues

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAppCues_Pattern(t *testing.T) {
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
				[INFO] Sending request to the appcues API
				[DEBUG] Using appcues Key=5g5n4yazu-dpqp3g6qt3gn59wrxhqf2mqipm
				[DEBUG] Using appcues User=truffle-security-lrv10a8l4u23xp5gkvg819
				[INFO] Response received: 200 OK
				[INFO] APPCUES_ID=57843
			`,
			want: []string{"5g5n4yazu-dpqp3g6qt3gn59wrxhqf2mqipmtruffle-security-lrv10a8l4u23xp5gkvg819"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{appcues 91712}</id>
					<username>{appcues ubdcpht45hlfdywxv89ympnvtcnydl3uv-0umfu}</username>
  					<secret>{appcues AQAAABAAA w9hyyfghqirj8uwcmtv05-n4fppzl-in223u}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"w9hyyfghqirj8uwcmtv05-n4fppzl-in223uubdcpht45hlfdywxv89ympnvtcnydl3uv-0umfu"},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the appcues API
				[DEBUG] Using appcues Key=5g5n4yazu-dpqp3g6qt3gn59wrxhqf2mqipm
				[DEBUG] Using appcues User=truffle_security-lrv10a8l4u23xp5gkvg819
				[ERROR] Response received: 401 UnAuthorized
				[INFO] ID=57843
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
