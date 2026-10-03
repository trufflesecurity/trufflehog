package hashicorpbatchtoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestBatchToken_PatternWithURL(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid hvb token with vault url",
			input: `
				func setupVaultClient() (*http.Client, error) {
					vaultAddr := "https://vault-cluster-abc123.hashicorp.cloud:8200"
					token := "hvb.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

					// Look up the token to confirm it's still valid
					req, err := http.NewRequest("GET", vaultAddr+"/v1/auth/token/lookup-self", http.NoBody)
					if err != nil {
						return nil, err
					}
					req.Header.Set("X-Vault-Token", token)

					client := &http.Client{}
					resp, _ := client.Do(req)
					defer func() { _ = resp.Body.Close() }()

					return client, nil
				}
				`,
			want: []string{
				"hvb.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:https://vault-cluster-abc123.hashicorp.cloud:8200",
			},
		},
		{
			name: "valid hvb token with longer length",
			input: `
				# vault-config.env
				VAULT_ADDR=https://vault-cluster-xyz.hashicorp.cloud
				VAULT_TOKEN=hvb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
				VAULT_NAMESPACE=admin
				`,
			want: []string{
				"hvb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:https://vault-cluster-xyz.hashicorp.cloud",
			},
		},
		{
			name: "token only, no URL",
			input: `
				func rotateVaultToken() {
					// Deprecated batch token retained for the audit trail
					oldToken := "hvb.cccccccccccccccccccccccccccccccccccccccccccccccccc"
					log.Println("token retired:", oldToken)
				}
				`,
			want: nil,
		},
		{
			name: "URL only, no token",
			input: `
				func vaultHealthCheck() error {
					resp, err := http.Get("https://vault-cluster-abc123.hashicorp.cloud:8200/v1/sys/health")
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
			name: "invalid token - too short",
			input: `
				func setupVaultClient() {
					vaultAddr := "https://vault-cluster-abc123.hashicorp.cloud"
					// Truncated token accidentally committed
					token := "hvb.shorttoken"
					client.SetToken(vaultAddr, token)
				}
				`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && len(test.want) > 0 {
				t.Errorf(
					"test %q failed: expected keywords %v to be found in the input",
					test.name,
					d.Keywords(),
				)
				return
			}

			d.UseFoundEndpoints(true)

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
