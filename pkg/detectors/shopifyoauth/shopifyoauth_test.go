package shopifyoauth

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestShopifyOAuth_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - all three components",
			input: `
				SHOPIFY_CLIENT_ID=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
				SHOPIFY_CLIENT_SECRET=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
				SHOPIFY_STORE=my-test-store.myshopify.com
			`,
			want: []string{"my-test-store.myshopify.com:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6: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"},
		},
		{
			name: "valid pattern - different context keywords",
			input: `
				client_id: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
				client_secret: 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
				store_url: example-shop.myshopify.com
			`,
			want: []string{"example-shop.myshopify.com:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6: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"},
		},
		{
			name: "valid pattern - multiple domains produce multiple results",
			input: `
				shopify_client_id=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
				client_secret=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
				store1: store-one.myshopify.com
				store2: store-two.myshopify.com
			`,
			want: []string{
				"store-one.myshopify.com:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6: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",
				"store-two.myshopify.com:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6: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",
			},
		},
		{
			name: "missing client secret - no results",
			input: `
				shopify_client_id=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
				store: test-store.myshopify.com
			`,
			want: []string{},
		},
		{
			name: "missing client id - no results",
			input: `
				client_secret=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
				store: test-store.myshopify.com
			`,
			want: []string{},
		},
		{
			name: "missing domain - no results",
			input: `
				shopify_client_id=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
				client_secret=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
			`,
			want: []string{},
		},
		{
			name: "invalid secret prefix - no results",
			input: `
				shopify_client_id=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
				client_secret=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
				store: test-store.myshopify.com
			`,
			want: []string{},
		},
		{
			name: "client id without context keywords - no results",
			input: `
				random_key=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
				secret=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
				store: test-store.myshopify.com
			`,
			want: []string{},
		},
		{
			name: "valid pattern - JSON config",
			input: `{
				"shopify": {
					"client_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
					"client_secret": "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",
					"store_domain": "my-store.myshopify.com"
				}
			}`,
			want: []string{"my-store.myshopify.com:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6: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"},
		},
		{
			name: "valid pattern - uppercase hex in secret",
			input: `
				shopify_client_id=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
				secret=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
				url: test.myshopify.com
			`,
			want: []string{"test.myshopify.com:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6: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"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
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
