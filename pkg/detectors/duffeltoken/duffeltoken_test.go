package duffeltoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestDuffelTestToken_Pattern(t *testing.T) {
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
				func setupDuffelClient() (*http.Client, error) {
					url := "https://api.duffel.com/identity/customer/users?limit=1"

					// Create a new request with the secret as a header
					req, err := http.NewRequest("GET", url, http.NoBody)
					if err != nil {
						fmt.Println("Error creating request:", err)
						return nil, err
					}

					duffelToken := "duffel_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					req.Header.Set("Authorization", "Bearer "+duffelToken)
					req.Header.Set("Duffel-Version", "v2")

					// Perform the request
					client := &http.Client{}
					resp, _ := client.Do(req)
					defer func() { _ = resp.Body.Close() }()

					return client, nil
				}
				`,
			want: []string{
				"duffel_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
		{
			name: "valid pattern - env file",
			input: `
				# .env.production
				APP_NAME=flight-booker
				APP_ENV=production
				DUFFEL_API_TOKEN=duffel_test_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
				LOG_LEVEL=info
				`,
			want: []string{
				"duffel_test_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		{
			name: "valid pattern - multiple tokens",
			input: `
				func loadDuffelTokens() map[string]string {
					// Tokens for each deployment environment
					return map[string]string{
						"staging":    "duffel_test_ccccccccccccccccccccccccccccccccccccccccccc",
						"production": "duffel_live_ddddddddddddddddddddddddddddddddddddddddddd",
					}
				}
				`,
			want: []string{
				"duffel_test_ccccccccccccccccccccccccccccccccccccccccccc",
				"duffel_live_ddddddddddddddddddddddddddddddddddddddddddd",
			},
		},
		{
			name: "invalid pattern - too short",
			input: `
				func setupDuffelClient() {
					// Truncated token accidentally committed
					token := "duffel_test_abc123"
					client.SetAuthToken(token)
				}
				`,
			want: nil,
		},
		{
			name: "invalid pattern - invalid characters",
			input: `
				func setupDuffelClient() {
					// Token contains an invalid special character
					token := "duffel_test_aaaaaaaaaaaaaaaaaaaaaaa!aaaaaaaaaaaaaaaaaaa"
					client.SetAuthToken(token)
				}
				`,
			want: nil,
		},
		{
			name: "invalid pattern - keyword only",
			input: `
				// TODO: replace hardcoded duffel_test_ prefix check with proper validation
				func isDuffelTestToken(s string) bool {
					return strings.HasPrefix(s, "duffel_test_")
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
