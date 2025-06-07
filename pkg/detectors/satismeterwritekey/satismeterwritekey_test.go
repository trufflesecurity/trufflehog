package satismeterwritekey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	complexPattern = `
	func main() {
		url := "https://api.example.com/v1/resource"

		// Create a new request with the secret as a header
		req, err := http.NewRequest("GET", url, http.NoBody)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}
		
		satismeterToken := os.GetEnv("SATISMETER_TOKEN")
		if satismeterToken == ""{
			satismeterToken = "VVVCVDXuoVwRFAKEiCseXmDiaC32jq7x"
		}
		satismeter_projectID := "satismeter12345678901234"
		satismeter_writekey := "0TlknArPMr30WgJtL7SuM9V8LWGuqsxr"
		req.Header.Set("Authorization", "Basic " + satismeterToken)

		// Perform the request
		client := &http.Client{}
		resp, _ := client.Do(req)
		defer resp.Body.Close()

		// Check response status
		if resp.StatusCode == http.StatusNoContent {
			fmt.Println("Request successful!")
		} else {
			fmt.Println("Request failed with status:", resp.Status)
		}
	}
	`
	secrets = []string{
		"satismeter123456789012340TlknArPMr30WgJtL7SuM9V8LWGuqsxr",
		"satismeter12345678901234VVVCVDXuoVwRFAKEiCseXmDiaC32jq7x",
	}
)

func TestSatisMeterWriteKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: complexPattern,
			want:  secrets,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && test.want != nil {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
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
