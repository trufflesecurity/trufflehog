package billomat

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestBilloMat_Pattern(t *testing.T) {
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
						url := "https://api.billomat.net/v2/id/truffletest"

						// Create a new request with the secret as a header
						req, err := http.NewRequest("GET", url, http.NoBody)
						if err != nil {
							fmt.Println("Error creating request:", err)
							return
						}
						
						req.Header.Set("X-BillomatApiKey", "c09761f99f39f79ae28eaaf8df20d7c9")

						// Perform the request
						client := &http.Client{}
						resp, _ := client.Do(req)
						defer resp.Body.Close()

						// Check response status
						if resp.StatusCode == http.StatusOK {
							fmt.Println("Request successful!")
						} else {
							fmt.Println("Request failed with status:", resp.Status)
						}
					}`,
			want: []string{
				"c09761f99f39f79ae28eaaf8df20d7c9truffletest",
			},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{billomat m2o8fqf8}</id>
  					<secret>{billomat AQAAABAAA 36a584c280b5b617e8eb25dae6b64d63}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"36a584c280b5b617e8eb25dae6b64d63m2o8fqf8"},
		},
		{
			name: "invalid pattern",
			input: `
				req, err := http.NewRequest("GET", url, http.NoBody)
				if err != nil {
					fmt.Println("Error creating request:", err)
					return
				}
				req.Header.Set("X-BillomatApiKey", "c09761h99f39f79ae28eaaf8df20d7c9")
				billomatID := truffle-test
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
