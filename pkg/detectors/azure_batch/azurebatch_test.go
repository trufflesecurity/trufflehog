package azure_batch

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAzureBatch_Pattern(t *testing.T) {
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
				[INFO] Sending request to the ayrshare API
				[DEBUG] Using Secret = BXIMbhBlC3=5hIbqCEKvq7opaV2ZfO0XWbcnasZmPm/AJfQqdcnt/AVmKkJ8Qw80Zc1rQDaw+2Ytxc1hDq1m/LB0
				[INFO] https://JrxlYxT+0hW.YSA.batch.azure.com
				[INFO] Response received: 200 OK
			`,
			want: []string{"https://JrxlYxT+0hW.YSA.batch.azure.comBXIMbhBlC3=5hIbqCEKvq7opaV2ZfO0XWbcnasZmPm/AJfQqdcnt/AVmKkJ8Qw80Zc1rQDaw+2Ytxc1hDq1m/LB0"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{https://pb0bik2a59qznkh87pdd6twjlgzpmxz.pfv9bpr2hujs.batch.azure.com}</id>
  					<secret>{AQAAABAAA XJc2nGZvqPAXYfHxsiwUDBA4ynHzGc9nQl1Ih16lk19=2+qqeJUDp5eBxWVrE0LQYlnbeu/orbEtblFL218S4Wko}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"https://pb0bik2a59qznkh87pdd6twjlgzpmxz.pfv9bpr2hujs.batch.azure.comXJc2nGZvqPAXYfHxsiwUDBA4ynHzGc9nQl1Ih16lk19=2+qqeJUDp5eBxWVrE0LQYlnbeu/orbEtblFL218S4Wko"},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the ayrshare API
				[DEBUG] Using Secret=BXIMbhBlC3=5hIbqCEKvq7op!V2ZfO0XWbcnasZmPm/AJfQqdcnt/AVmKkJ8Qw80Zc1rQDaw+2Ytxc1hDq1m/
				[INFO] http://invalid.this.batch.azure.com
				[INFO] Response received: 200 OK
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
