package bulbul

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestBulBul_Pattern(t *testing.T) {
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
					url := "https://api.bulbul.com/v1/users?key=3kx19qpx748ldb75lsjicbs6ipit6ssm"

					// Create a new request with the secret as a header
					req, err := http.NewRequest("GET", url, http.NoBody)
					if err != nil {
						fmt.Println("Error creating request:", err)
						return
					}

					// Perform the request
					client := &http.Client{}
					resp, _ := client.Do(req)
					defer resp.Body.Close()
				}
				`,
			want: []string{"3kx19qpx748ldb75lsjicbs6ipit6ssm"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{bulbul}</id>
  					<secret>{bulbul AQAAABAAA r9gk8o0ctd4xq4r66d3reahu9ku4i4ht}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"r9gk8o0ctd4xq4r66d3reahu9ku4i4ht"},
		},
		{
			name: "invalid pattern",
			input: `
				func main() {
					url := "https://api.bulbul.com/v1/users?key=%c^wz9450iu-3kx19qcbs6ipit6ssm-jonx-eab8"

					// Create a new request with the secret as a header
					req, err := http.NewRequest("GET", url, http.NoBody)
					if err != nil {
						fmt.Println("Error creating request:", err)
						return
					}

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
