package atlassian

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAtlassian_Pattern(t *testing.T) {
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
				[INFO] Sending request to the atlassian API
				[DEBUG] Using Key=ATCTT3xFfGN0GsZNgOGrQSHSnxiJVi00oHlRicyM0yMNuKCBfw6qOHVcCy4Hm89GnclGb_W-1qAkxqCn5XbuyoX54bNhpK5yFKGFR7ocV6FByvL_P9Sb3tFnbUg3T3I3S_RGCBLMSN7Nsa4GJv8JEJ6bzvDmX-oJ8AnrazMU-zZ5hb-u3t2ERew=366BFE3A
				[INFO] Response received: 200 OK
				`,
			want: []string{"ATCTT3xFfGN0GsZNgOGrQSHSnxiJVi00oHlRicyM0yMNuKCBfw6qOHVcCy4Hm89GnclGb_W-1qAkxqCn5XbuyoX54bNhpK5yFKGFR7ocV6FByvL_P9Sb3tFnbUg3T3I3S_RGCBLMSN7Nsa4GJv8JEJ6bzvDmX-oJ8AnrazMU-zZ5hb-u3t2ERew=366BFE3A"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{98651}</id>
  					<secret>{AQAAABAAA ATCTT3xFfGXc59Vkq40qLX=iEOIrJRZ}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"ATCTT3xFfGXc59Vkq40qLX=iEOIrJRZ"},
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
