package borgbase

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestBorgBase_Pattern(t *testing.T) {
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
				func main() {
					url := "https://api.example.com/v1/resource"

					// Create a new request with the secret as a header
					payload := '{"query":"{ sshList {id, name}}"}'
					req, err := http.NewRequest("POST", url, payload)
					if err != nil {
						fmt.Println("Error creating request:", err)
						return
					}
					
					borgbaseToken := "FoHclCFSi_aV09jowJQ4RUF_MiqW6ioqq6_OcyB0PFlV-mQ1yoFjk5JLlxbzRUzKTA6vsfR8wq6TNc83rtNKlkD092Sj1c9CbPVBXlHksy.sT2I/so6bMGdPcqxzbjrxYgAUiORgqJDeTet4gKOQlZpt"
					req.Header.Set("Authorization", "Bearer " + borgbaseToken)

					// Perform the request
					client := &http.Client{}
					resp, _ := client.Do(req)
					defer resp.Body.Close()
				}
				`,
			want: []string{"FoHclCFSi_aV09jowJQ4RUF_MiqW6ioqq6_OcyB0PFlV-mQ1yoFjk5JLlxbzRUzKTA6vsfR8wq6TNc83rtNKlkD092Sj1c9CbPVBXlHksy.sT2I/so6bMGdPcqxzbjrxYgAUiORgqJDeTet4gKOQlZpt"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{borgbase}</id>
  					<secret>{borgbase AQAAABAAA KtSE0ggsVsvvDQPHau2ItXW8yi7YsFTho4wHTTjCDShrWgYA421GzfXMwkOYklS6psQd1W8459NvmcZSmr7_LKqQffBGYAVvexM1D4JxRcQS49H3rnFlwDYspB5_m7AxvmbPrpWj8TfNm7zKCa2Ed}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"KtSE0ggsVsvvDQPHau2ItXW8yi7YsFTho4wHTTjCDShrWgYA421GzfXMwkOYklS6psQd1W8459NvmcZSmr7_LKqQffBGYAVvexM1D4JxRcQS49H3rnFlwDYspB5_m7AxvmbPrpWj8TfNm7zKCa2Ed"},
		},
		{
			name: "invalid pattern",
			input: `
				func main() {
					url := "https://api.example.com/v1/resource"

					// Create a new request with the secret as a header
					payload := '{"query":"{ sshList {id, name}}"}'
					req, err := http.NewRequest("POST", url, payload)
					if err != nil {
						fmt.Println("Error creating request:", err)
						return
					}
					
					borgbaseToken := "mQ1yoFjk5JLlxbzRUzKTA6vsfR8wq,6TNc83rtNKlkD092Sj1c9CbPVBXlHksy%c^so6bMGdPcqxzbjrxYgAUiORgqJDeTet4gKOQlZpt"
					req.Header.Set("Authorization", "Bearer " + borgbaseToken)

					// Perform the request
					client := &http.Client{}
					resp, _ := client.Do(req)
					defer resp.Body.Close()
				}
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
