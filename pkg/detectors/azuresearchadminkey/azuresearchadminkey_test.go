package azuresearchadminkey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAzureSearchAdminKey_Pattern(t *testing.T) {
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
				azure:
					azureKey: wRRPyhjv8m6JGRujUUrPKa8d3rJ0mrGAxhmqf3A68OgZmlWUJyma
					azureService: TestingService01
				`,
			want: []string{"wRRPyhjv8m6JGRujUUrPKa8d3rJ0mrGAxhmqf3A68OgZmlWUJymaTestingService01", "wRRPyhjv8m6JGRujUUrPKa8d3rJ0mrGAxhmqf3A68OgZmlWUJymaazureKey"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{azure bhIIhGTLlW7gLxy4rM93gLPaPFwdRajJX}</id>
  					<secret>{azure AQAAABAAA Pntv3pDD31oczaYT99OanBBZyYlnKGUpQb4WEFnK6uUsKiR0Mc09}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{
				"Pntv3pDD31oczaYT99OanBBZyYlnKGUpQb4WEFnK6uUsKiR0Mc09bhIIhGTLlW7gLxy4rM93gLPaPFwdRajJX",
				"Pntv3pDD31oczaYT99OanBBZyYlnKGUpQb4WEFnK6uUsKiR0Mc09AQAAABAAA",
			},
		},
		{
			name: "invalid pattern",
			input: `
				azure:
					Key: wRRPyhjv8m6JGRujUUr-PK#a8d3rJ0mrGAxhmqf3A68OgZmlWUJyma
					Service: TS01
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
