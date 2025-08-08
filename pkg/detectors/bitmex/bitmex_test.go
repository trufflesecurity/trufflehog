package bitmex

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestBitmex_Pattern(t *testing.T) {
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
					
					bitmexKey := " EPwUIxOIveS463D_2O9LFgkz "
					bitmexSecret := " W_HlMtrmELzXm4bSlWv49JLcgvg5hvu467WbbnpmoEA-RjrY "

					signature, err := generateSecretSignature(bitmexKey, bitmexSecret)
					if err != nil{
						return err
					}

					req.Header.Set("api-signature", signature)

					// Perform the request
					client := &http.Client{}
					resp, _ := client.Do(req)
					defer resp.Body.Close()
				}
				`,
			want: []string{"EPwUIxOIveS463D_2O9LFgkzW_HlMtrmELzXm4bSlWv49JLcgvg5hvu467WbbnpmoEA-RjrY"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{bitmex EPwUIxOIveS463D_2O9LFgkz }</id>
  					<secret>{bitmex AQAAABAAA W_HlMtrmELzXm4bSlWv49JLcgvg5hvu467WbbnpmoEA-RjrY }</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"EPwUIxOIveS463D_2O9LFgkzW_HlMtrmELzXm4bSlWv49JLcgvg5hvu467WbbnpmoEA-RjrY"},
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
					
					bitmexKey := "mELzXm4bSlWv49JLc%c^"
					bitmexSecret := "IXpH-fJJiLFn--Wo7rnlXE"

					signature, err := generateSecretSignature(bitmexKey, bitmexSecret)
					if err != nil{
						return err
					}

					req.Header.Set("api-signature", signature)

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
