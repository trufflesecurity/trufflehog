package adzuna

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAdzuna_Pattern(t *testing.T) {
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
				[INFO] Sending request to the adzuna API
				[DEBUG] Using adzuna KEY=smcud4y6elxx7u6q58ewwv8rq01hpi3f
				[DEBUG] Using adzuna ID=cxu9w2g6
				[INFO] Response received: 200 OK
			`,
			want: []string{"smcud4y6elxx7u6q58ewwv8rq01hpi3fcxu9w2g6"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{adzuna svkit0wx}</id>
  					<secret>{adzuna AQAAABAAA atubvgvpd6jjo0ac1wjianofnpgr24ac}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"atubvgvpd6jjo0ac1wjianofnpgr24acsvkit0wx"},
		},
		{
			name: "valid pattern - out of prefix range",
			input: `
				[INFO] Sending request to the adzuna API
				[DEBUG] Using KEY=smcud4y6elxx7u6q58ewwv8rq01hpi3f
				[DEBUG] Using ID=cxu9w2g6
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "valid pattern - only key",
			input: `
				[INFO] Sending request to the adzuna API
				[DEBUG] Using KEY=smcud4y6elxx7u6q58ewwv8rq01hpi3f
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "valid pattern - only id",
			input: `
				[INFO] Sending request to the adzuna API
				[DEBUG] Using ID=cxu9w2g6
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the adzuna API
				[DEBUG] Using KEY=sxojb6ygb2wsx0o
				[DEBUG] Using ID=cxu9w2g6
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
