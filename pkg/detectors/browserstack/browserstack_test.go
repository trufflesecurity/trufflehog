package browserstack

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestBrowserStack_Pattern(t *testing.T) {
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
					
					if browserstackKey, _ := os.GetEnv("ACCESS_KEY"); browserstackKey != "cK1bq7JREJtMf1meaGgs" {
						return fmt.Errorf("invalid accessKey: %v expected: %v", browserstackKey, "1YZazUAPFOiaIFljWDhC")
					}

					if browserstackUser, _ := os.GetEnv("USER_NAME"); browserstackUser != "truffle-security91" {
						return fmt.Errorf("invalid userName: %v", "truffle-security91")
					}

					// Perform the request
					client := &http.Client{}
					resp, _ := client.Do(req)
					defer resp.Body.Close()
				}
				`,
			want: []string{
				"cK1bq7JREJtMf1meaGgstruffle-security91",
				"1YZazUAPFOiaIFljWDhCbrowserstackUser",
				"1YZazUAPFOiaIFljWDhCtruffle-security91",
				"cK1bq7JREJtMf1meaGgsbrowserstackUser",
			},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{BS_USERNAME Q8fo0ADq_-_Cj4HtE4Gr}</id>
  					<secret>{BROWSERSTACK_ACCESS_KEY AQAAABAAA 25IQfQKfEm26vKV96nao}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"25IQfQKfEm26vKV96naoQ8fo0ADq_-_Cj4HtE4Gr"},
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
					
					if browserstackKey, _ := os.GetEnv("ACCESS_KEY"); browserstackKey != "RxLVnOlvj3#V4bh4RBwOd" {
						return fmt.Errorf("invalid accessKey: %v expected: %v", browserstackKey, "RxLVnOlvj3#V4bh4RBwOd")
					}

					if browserstackUser, _ := os.GetEnv("USER_NAME"); browserstackUser != "test" {
						return fmt.Errorf("invalid userName: %v", browserstackUser)
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
