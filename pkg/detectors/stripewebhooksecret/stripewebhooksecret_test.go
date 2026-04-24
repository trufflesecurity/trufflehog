package stripewebhooksecret

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestStripeWebhookSecret_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern 32-char base64-style",
			input: `
				[INFO] Configuring Stripe webhook
				[DEBUG] endpoint_secret=whsec_abcdefghijklmnopqrstuvwxyz012345
				[INFO] Webhook ready
			`,
			want: []string{"whsec_abcdefghijklmnopqrstuvwxyz012345"},
		},
		{
			name: "valid pattern 64-char base64-style with uppercase and plus",
			input: `
				[INFO] Configuring Stripe webhook
				[DEBUG] endpoint_secret=whsec_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789++
				[INFO] Webhook ready
			`,
			want: []string{"whsec_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789++"},
		},
		{
			name: "valid pattern stripe-cli-style (hex)",
			input: `
				[INFO] Configuring Stripe webhook
				[DEBUG] endpoint_secret=whsec_7e6a1452a9117826e207a03c19a965e81e65f30a96aa06bbc09b6745cf77bef
				[INFO] Webhook ready
			`,
			want: []string{"whsec_7e6a1452a9117826e207a03c19a965e81e65f30a96aa06bbc09b6745cf77bef"},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Configuring Stripe webhook
				[DEBUG] endpoint_secret=whsec_!!invalid!!short
				[ERROR] Signature verification failed
			`,
			want: []string{},
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
