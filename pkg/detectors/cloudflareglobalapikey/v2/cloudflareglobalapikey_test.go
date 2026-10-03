package cloudflareglobalapikey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestCloudFlareGlobalAPIKeyV2_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid v2 pattern - curl script with account email",
			input: `
				#!/usr/bin/env bash
				# purge-cache.sh - flushes the edge cache for the production zone
				set -euo pipefail

				curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/purge_cache" \
					-H "X-Auth-Email: testuser1005@example.com" \
					-H "X-Auth-Key: cfk_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfe" \
					-H "Content-Type: application/json" \
					--data '{"purge_everything":true}'
				`,
			want: []string{
				"cfk_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfetestuser1005@example.com",
			},
		},
		{
			name: "valid v2 pattern - env file, no email nearby still emits result",
			input: `
				# .env.production
				APP_NAME=edge-cache-worker
				CLOUDFLARE_API_KEY=cfk_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfe
				LOG_LEVEL=info
				`,
			want: []string{
				"cfk_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfe",
			},
		},
		{
			name: "no match for legacy format",
			input: `
				# .env.legacy
				# Pre-2026 global API keys are bare 37-char hex strings without a prefix.
				CLOUDFLARE_API_KEY=abcdef1234567890abcdef1234567890abcdef0
				CLOUDFLARE_EMAIL=testuser1005@example.com
				`,
			want: nil,
		},
		{
			name: "valid pattern - ansible playbook rotating keys across environments",
			input: `
				---
				- name: Rotate Cloudflare global API keys
				  hosts: localhost
				  vars:
				    staging_key: "cfk_fygw2wMqZcUDIh7yfJs1ON43xKmTecQoXsf2o3gy8eb5bb68"
				    production_key: "cfk_S7RPeMOkIUpkDyr7OSJoRu1XXdo0cZuzren68K4Ta6fce484"
				  tasks:
				    - name: Update staging secret store
				      command: "vault kv put secret/staging cf_key={{ staging_key }}"
				    - name: Update production secret store
				      command: "vault kv put secret/production cf_key={{ production_key }}"
				`,
			want: []string{
				"cfk_fygw2wMqZcUDIh7yfJs1ON43xKmTecQoXsf2o3gy8eb5bb68",
				"cfk_S7RPeMOkIUpkDyr7OSJoRu1XXdo0cZuzren68K4Ta6fce484",
			},
		},
		{
			name: "invalid pattern - too short",
			input: `
				func setupCloudflareClient() {
					// Truncated key accidentally committed during a config export
					key := "cfk_ZE4CrcFhEIDXk9vL2sTLe"
					client.SetGlobalKey(key)
				}
				`,
			want: nil,
		},
		{
			name: "invalid pattern - too long",
			input: `
				func setupCloudflareClient() {
					// Extra characters appended by a bad find-and-replace
					key := "cfk_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfeEXTRA"
					client.SetGlobalKey(key)
				}
				`,
			want: nil,
		},
		{
			name: "invalid pattern - invalid characters",
			input: `
				func setupCloudflareClient() {
					// Key was mangled when pasted from a Slack message with markdown formatting
					key := "cfk_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbf!"
					client.SetGlobalKey(key)
				}
				`,
			want: nil,
		},
		{
			name: "invalid pattern - keyword only",
			input: `
				// TODO: load the real key instead of reading cfk_ from env
				func isCloudflareGlobalKey(s string) bool {
					return strings.HasPrefix(s, "cfk_")
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
