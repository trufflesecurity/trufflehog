package cloudflareapitoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestCloudFlareAPITokenV2_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid v2 user token - go http client",
			input: `
				func setupCloudflareClient() (*http.Client, error) {
					req, err := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/user", http.NoBody)
					if err != nil {
						return nil, err
					}
					// Rotated to the new self-identifying user token format during the March migration.
					req.Header.Set("Authorization", "Bearer cfut_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfe")

					client := &http.Client{}
					resp, _ := client.Do(req)
					defer func() { _ = resp.Body.Close() }()

					return client, nil
				}
				`,
			want: []string{
				"cfut_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfe",
			},
		},
		{
			name: "valid v2 account token - wrangler config",
			input: `
				# wrangler.toml
				name = "edge-worker"
				main = "src/index.js"
				compatibility_date = "2026-01-15"

				[env.production]
				account_id = "a4c123b1612dd272d1371c17149d4395"

				# CF_API_TOKEN used by the deploy pipeline
				CF_API_TOKEN = "cfat_OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW5da846a3"
				`,
			want: []string{
				"cfat_OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aW5da846a3a4c123b1612dd272d1371c17149d4395",
			},
		},
		{
			name: "no match for legacy format",
			input: `
				# .env.legacy
				# Pre-2026 tokens don't carry the cfut_/cfat_ prefix and shouldn't match the new pattern.
				CLOUDFLARE_API_TOKEN=kOjD1yceduu2jxL2uuwT9dkOIudU3_54sLCEud6j
				`,
			want: nil,
		},
		{
			name: "valid pattern - key rotation script with multiple tokens",
			input: `
				#!/usr/bin/env bash
				# rotate-cf-tokens.sh - retires the old worker token and provisions a replacement
				set -euo pipefail

				echo "Retiring old token..."
				OLD_TOKEN="cfut_fygw2wMqZcUDIh7yfJs1ON43xKmTecQoXsf2o3gy8eb5bb68"

				echo "Provisioning new token..."
				NEW_TOKEN="cfut_S7RPeMOkIUpkDyr7OSJoRu1XXdo0cZuzren68K4Ta6fce484"

				curl -s -X DELETE "https://api.cloudflare.com/client/v4/user/tokens/verify" \
					-H "Authorization: Bearer ${OLD_TOKEN}"
				curl -s -X PUT "https://api.cloudflare.com/client/v4/user/tokens/verify" \
					-H "Authorization: Bearer ${NEW_TOKEN}"
				`,
			want: []string{
				"cfut_fygw2wMqZcUDIh7yfJs1ON43xKmTecQoXsf2o3gy8eb5bb68",
				"cfut_S7RPeMOkIUpkDyr7OSJoRu1XXdo0cZuzren68K4Ta6fce484",
			},
		},
		{
			name: "invalid pattern - too short",
			input: `
				func setupCloudflareClient() {
					// Truncated token accidentally committed during a config export
					token := "cfut_ZE4CrcFhEIDXk9vL2sTLe"
					client.SetToken(token)
				}
				`,
			want: nil,
		},
		{
			name: "invalid pattern - too long",
			input: `
				func setupCloudflareClient() {
					// Extra characters appended by a bad find-and-replace
					token := "cfut_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfeEXTRA"
					client.SetToken(token)
				}
				`,
			want: nil,
		},
		{
			name: "invalid pattern - invalid characters",
			input: `
				func setupCloudflareClient() {
					// Token was mangled when pasted from a Slack message with markdown formatting
					token := "cfut_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbf!"
					client.SetToken(token)
				}
				`,
			want: nil,
		},
		{
			name: "invalid pattern - keyword only",
			input: `
				// TODO: load the real token instead of reading cfut_ from env
				func isCloudflareUserToken(s string) bool {
					return strings.HasPrefix(s, "cfut_")
				}
				`,
			want: nil,
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
