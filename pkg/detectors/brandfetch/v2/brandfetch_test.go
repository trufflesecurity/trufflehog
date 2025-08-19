package brandfetch

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestBrandFetch_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: "brandfetch credentials: ZUfake+eKo3qNxLDfake/6vqjOtr4fa6u5wShfakes8=",
			want:  []string{"ZUfake+eKo3qNxLDfake/6vqjOtr4fa6u5wShfakes8="},
		},
		{
			name:  "valid pattern - assignment format",
			input: "BRANDFETCH_API_KEY=msCwufakeod43s2ad/D0em/LbIBpZqFAKE9P+H3UTno=",
			want:  []string{"msCwufakeod43s2ad/D0em/LbIBpZqFAKE9P+H3UTno="},
		},
		{
			name: "valid pattern - complex",
			input: `
			func main() {
				url := "https://api.example.com/v1/resource"

				// Create a new request with the secret as a header
				req, err := http.NewRequest("GET", url, http.NoBody)
				if err != nil {
					fmt.Println("Error creating request:", err)
					return
				}
				
				brandfetchAPIKey := "0mWrufake4X1dRfake0mxS+E48ofakesTlyl55raNOs="
				req.Header.Set("x-api-key", brandfetchAPIKey) // brandfetch secret

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
			}
			`,
			want: []string{"0mWrufake4X1dRfake0mxS+E48ofakesTlyl55raNOs="},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{uSiXZ-NMpDW-ZJQFSN-5wkT7SqQ8-mDbr9K2pl}</id>
  					<secret>{brandfetch AQAAABAAA 0mWrufake4X1dRfake0mxS+E48ofakesTlyl55rfake=}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"0mWrufake4X1dRfake0mxS+E48ofakesTlyl55rfake="},
		},
		{
			name:  "invalid pattern - wrong length",
			input: "brandfetch credentials: yUeIqnFwILOIlEPyBt+=JOAdwfQ7sD2uHOAdwf2U",
			want:  nil,
		},
		{
			name:  "invalid pattern - invalid characters",
			input: "brandfetch credentials: yUeIqnFwILOIlEPyBt+=JOAdwfQ7sD2uHOAdwf2U[qy]UeIqnFwILOIlEPyBtJ^fakes=",
			want:  nil,
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
					
					brandfetchAPIKey := "yUeIqnFwILOIlEPyBt+=JOAdwfQ7sD2uHOAdwf2U[qy]UeIqnFwILOIlEPyBtJ^"
					req.Header.Set("x-api-key", brandfetchAPIKey) // brandfetch secret

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
