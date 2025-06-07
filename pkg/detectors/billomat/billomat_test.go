package billomat

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "billomatKey: xv3khh5klgzztdmptrgbqhkr0ucvr67i / billomatID: s2mels7c75tnsbs7ldu0wmjofzmugkg7vb"
	complexPattern = `
	func main() {
		url := "https://api.billomat.net/v2/s2mels7c75tnsbs7ldu0wmjofzmugkg7vb"

		// Create a new request with the secret as a header
		req, err := http.NewRequest("GET", url, http.NoBody)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}
		
		req.Header.Set("X-BillomatApiKey", "xv3khh5klgzztdmptrgbqhkr0ucvr67i")

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
	`
	invalidPattern = "billomat_creds: s2mels7c75tnsbs7ldu0wmjofzmugkg7vb"
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
			name:  "valid pattern",
			input: validPattern,
			want: []string{
				"xv3khh5klgzztdmptrgbqhkr0ucvr67is2mels7c75tnsbs7ldu0wmjofzmugkg7vb",
				"xv3khh5klgzztdmptrgbqhkr0ucvr67ixv3khh5klgzztdmptrgbqhkr0ucvr67i",
			},
		},
		{
			name:  "valid pattern - complex",
			input: complexPattern,
			want: []string{
				"xv3khh5klgzztdmptrgbqhkr0ucvr67inet",
				"xv3khh5klgzztdmptrgbqhkr0ucvr67ixv3khh5klgzztdmptrgbqhkr0ucvr67i",
			},
		},
		{
			name:  "invalid pattern",
			input: invalidPattern,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
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
