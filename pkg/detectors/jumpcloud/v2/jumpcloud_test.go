package jumpcloud

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestJumpCloudV2_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - env var",
			input: `
				# JumpCloud API configuration
				export JUMPCLOUD_API_KEY="jca_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
			`,
			want: []string{"jca_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"},
		},
		{
			name: "valid pattern - config file",
			input: `
				api_key: jca_r7m2Xk9pL4nQ8vB3wF6yH1jD5sA0tC2eG4iK
				server: https://console.jumpcloud.com
			`,
			want: []string{"jca_r7m2Xk9pL4nQ8vB3wF6yH1jD5sA0tC2eG4iK"},
		},
		{
			name: "valid pattern - code usage",
			input: `
				func main() {
					req, _ := http.NewRequest("GET", "https://console.jumpcloud.com/api/v2/systemgroups", nil)
					req.Header.Set("x-api-key", "jca_Tm4nQ8vB3wF6yH1jD5sA0tC2eG4iK7oUp9xL")
					client := &http.Client{}
					resp, _ := client.Do(req)
					defer func() { _ = resp.Body.Close() }()
				}
			`,
			want: []string{"jca_Tm4nQ8vB3wF6yH1jD5sA0tC2eG4iK7oUp9xL"},
		},
		{
			name: "valid pattern - deduplicates",
			input: `
				primary = "jca_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
				backup  = "jca_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
			`,
			want: []string{"jca_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"},
		},
		{
			name:  "invalid pattern - too short",
			input: `jca_aBcDeFgHiJkLmNoPqRsTuVwXyZ12345`,
			want:  nil,
		},
		{
			name:  "invalid pattern - too long",
			input: `jca_aBcDeFgHiJkLmNoPqRsTuVwXyZ12345678901`,
			want:  nil,
		},
		{
			name:  "invalid pattern - special characters",
			input: `jca_aBcDeFgHi-kLmNoPqRsTuVwXyZ123456789!`,
			want:  nil,
		},
		{
			name:  "invalid pattern - no jca_ prefix",
			input: `JUMPCLOUD_API_KEY=aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				if len(test.want) > 0 {
					t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				}
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

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
