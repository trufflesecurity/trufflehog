package bulksms

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestBulkSMS_Pattern(t *testing.T) {
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
					req, err := http.NewRequest("GET", url, http.NoBody)
					if err != nil {
						fmt.Println("Error creating request:", err)
						return
					}
					
					bulksmsKey := "(QGxPqRyzvt%xEKcV&#ePJGn)k0d9a"
					bulksmsID := "381A26C47380B85F2DB572314-ACBDC267B-8"

					req.SetBasicAuth(bulksmsKey, bulksmsID)

					// Perform the request
					client := &http.Client{}
					resp, _ := client.Do(req)
					defer resp.Body.Close()
				}
				`,
			want: []string{"QGxPqRyzvt%xEKcV&#ePJGn)k0d9a381A26C47380B85F2DB572314-ACBDC267B-8"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{bulksms fXHnHK&cN8H!1r5ersTDIe6ZJ8j51}</id>
  					<secret>{bulksms AQAAABAAA 04A1ED4D90D3E17-3968-66B6A571D--2134E}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"fXHnHK&cN8H!1r5ersTDIe6ZJ8j5104A1ED4D90D3E17-3968-66B6A571D--2134E"},
		},
		{
			name: "invalid pattern",
			input: `
				func main() {
					url := "https://api.example.com/v1/resource"

					// Create a new request with the secret as a header
					req, err := http.NewRequest("GET", url, http.NoBody)
					if err != nil {
						fmt.Println("Error creating request:", err)
						return
					}
					
					bulksmsKey := "(QGxPqRyzvt%xEKcV&#ePJGn)k0d9a"
					bulksmsID := "%c^wz9450iu-iewm-jonx-eab8-/F2DB572314-ACBDC267B-8"

					req.SetBasicAuth(bulksmsKey, bulksmsID)

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
