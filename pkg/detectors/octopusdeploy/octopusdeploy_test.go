package octopusdeploy

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestOctopusDeploy_Pattern(t *testing.T) {
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
				func setupOctopusClient() (*http.Client, error) {
					baseUrl := &url.URL{Scheme: "https", Host: "acme.octopus.app", Path: "/api/users/me"}

					// Create a new request with the API key as a header
					req, err := http.NewRequest("GET", baseUrl.String(), http.NoBody)
					if err != nil {
						return nil, err
					}
					req.Header.Set("X-Octopus-ApiKey", "API-1234567890ABCDEFGHIJKLMNO1234")

					client := &http.Client{}
					resp, _ := client.Do(req)
					defer func() { _ = resp.Body.Close() }()

					return client, nil
				}
				`,
			want: []string{
				"acme.octopus.app:API-1234567890ABCDEFGHIJKLMNO1234",
			},
		},
		{
			name: "valid pattern - env file",
			input: `
				# .env.production
				APP_NAME=deploy-bot
				OCTOPUS_URL=prod.octopus.app
				OCTOPUS_API_KEY=API-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				LOG_LEVEL=info
				`,
			want: []string{
				"prod.octopus.app:API-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
		},
		{
			name: "valid pattern - multiple tokens",
			input: `
				func loadOctopusKeys() []string {
					// Rotated keys retained during the grace period
					return []string{
						"API-11111111111111111111111111111",
						"API-22222222222222222222222222222",
					}
				}

				// deployments run against dev.octopus.app
				`,
			want: []string{
				"dev.octopus.app:API-11111111111111111111111111111",
				"dev.octopus.app:API-22222222222222222222222222222",
			},
		},
		{
			name: "valid pattern - multiple urls and tokens",
			input: `
				environments:
					- name: staging
						url: acme.octopus.app
					- name: production
						url: prod.octopus.app

				# shared deployment key used across environments
				api_key: API-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA
				`,
			want: []string{
				"acme.octopus.app:API-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"prod.octopus.app:API-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
		},
		{
			name: "invalid pattern - lowercase token",
			input: `
				func setupOctopusClient() {
					baseUrl := "acme.octopus.app"
					// Key was accidentally lowercased during a config export
					apiKey := "API-abcdefghijklmnopqrstuvwxyz1234"
					client.SetApiKey(baseUrl, apiKey)
				}
				`,
			want: nil,
		},
		{
			name: "invalid pattern - too short",
			input: `
				func setupOctopusClient() {
					baseUrl := "acme.octopus.app"
					// Truncated key accidentally committed
					apiKey := "API-1234"
					client.SetApiKey(baseUrl, apiKey)
				}
				`,
			want: nil,
		},
		{
			name: "invalid pattern - too long",
			input: `
				func setupOctopusClient() {
					baseUrl := "acme.octopus.app"
					// Extra characters appended by a bad find-and-replace
					apiKey := "API-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
					client.SetApiKey(baseUrl, apiKey)
				}
				`,
			want: nil,
		},
		{
			name: "invalid pattern - url only",
			input: `
				func octopusHealthCheck() error {
					resp, err := http.Get("https://acme.octopus.app/api/status")
					if err != nil {
						return err
					}
					defer func() { _ = resp.Body.Close() }()
					return nil
				}
				`,
			want: nil,
		},
		{
			name: "invalid pattern - token only",
			input: `
				// TODO: load the real key instead of octopus_token env var
				func isOctopusToken(s string) bool {
					return strings.HasPrefix(s, "API-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
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
				t.Errorf(
					"mismatch in result count: expected %d, got %d",
					len(test.want),
					len(results),
				)
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				actual[string(r.RawV2)] = struct{}{}
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
