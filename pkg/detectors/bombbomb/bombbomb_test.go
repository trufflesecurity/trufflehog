package bombbomb

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "HUmGL.17uQMEShYp2RVMR8vypd1iqj6FZcKkQ4SazuMkbEKhzRFKuvOiwYmNWPSvkE4wiLOv-zWTkK1WkVTScRb9_io0_kvhYX31tpwR3lAJUh27RJzf1BehaJTQDXhJB6aT2gQ2LMT7dda-b3vhmEuZHzPV9AMLV6cOrcqOTkK60vMcB0PTLRQ3c_kY.a.9.hRvgogdlI8mQJrzD0myPBY7lMpjpkcskQDpOgz2I37kNDYhf7IxT6sG-a7rI1LdpJ6HhJacktlNJSswST9jbt4A0ropfJJTHGny2aId4WyPpAnQubM98F1BUnyhfkDzenaUuuQ_ZoPn9mAOsdLQUlAyp4I9oLJ_v8yQ0Q4M.Yujscho9G4ZbVTInC2mP8taCPZdRK5qt-UfAF0CX9B4E0F9NItMUbRdbm3xIkl8C6iPUcgY5OTQDBSJRLKBJgIaEyyXe10pPw.qOUhLKNPcg5qPs1xhgBsZKfW2hNTff2dCL5h6E.940ojPuT0Iw90Q8kpQ2UzeUJrhXH9_GUANKA.pjD0-YcGpnlVEDouyXaXowUoh8pLqD-BtBQfteqyFqz7THGDvQKikMy7wiBuJAo0HttMG3jw1zKtA3gM6_VIXo_K4WN6yz8Ow4n5f6Unn5zn4j2haKA4WWI5-1c8-mm7SF5VqYJVz42wBmRqB6MWXegJ7yLt_EoG1tJHftnHZ"
	complexPattern = `
	func main() {
		url := "https://api.example.com/v1/resource"

		// Create a new request with the secret as a header
		req, err := http.NewRequest("GET", url, http.NoBody)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}
		
		bombbombToken := "HUmGL.17uQMEShYp2RVMR8vypd1iqj6FZcKkQ4SazuMkbEKhzRFKuvOiwYmNWPSvkE4wiLOv-zWTkK1WkVTScRb9_io0_kvhYX31tpwR3lAJUh27RJzf1BehaJTQDXhJB6aT2gQ2LMT7dda-b3vhmEuZHzPV9AMLV6cOrcqOTkK60vMcB0PTLRQ3c_kY.a.9.hRvgogdlI8mQJrzD0myPBY7lMpjpkcskQDpOgz2I37kNDYhf7IxT6sG-a7rI1LdpJ6HhJacktlNJSswST9jbt4A0ropfJJTHGny2aId4WyPpAnQubM98F1BUnyhfkDzenaUuuQ_ZoPn9mAOsdLQUlAyp4I9oLJ_v8yQ0Q4M.Yujscho9G4ZbVTInC2mP8taCPZdRK5qt-UfAF0CX9B4E0F9NItMUbRdbm3xIkl8C6iPUcgY5OTQDBSJRLKBJgIaEyyXe10pPw.qOUhLKNPcg5qPs1xhgBsZKfW2hNTff2dCL5h6E.940ojPuT0Iw90Q8kpQ2UzeUJrhXH9_GUANKA.pjD0-YcGpnlVEDouyXaXowUoh8pLqD-BtBQfteqyFqz7THGDvQKikMy7wiBuJAo0HttMG3jw1zKtA3gM6_VIXo_K4WN6yz8Ow4n5f6Unn5zn4j2haKA4WWI5-1c8-mm7SF5VqYJVz42wBmRqB6MWXegJ7yLt_EoG1tJHftnHZ"
		req.Header.Set("Authorization", bombbombToken)

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
	invalidPattern = "17uQMEShYp2RVMR8vypd1iqj6FZcKkQ4SazuMkbEKhzRFKuvOiwYmNWPSvkE4wiLOv%c^zWTkK1WkVTScRb9_io0_kvhYX31tpwR3lAJUh27RJzf1BehaJTQDXhJB6aT2gQ2LMT7dda"
)

func TestBombBomb_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("bombbomb credentials: %s", validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - complex",
			input: complexPattern,
			want:  []string{validPattern},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("bombbomb credentials: %s", invalidPattern),
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
