package stripepaymentintent

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestStripepaymentintent_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name          string
		input         string
		expectedPairs []string
	}{
		{
			name: "client secret with secret key",
			input: "stripepaymentintent_token = '" + "pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" +
				"' and stripe_key = '" + "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" + "'",
			expectedPairs: []string{"pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" +
				"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"},
		},
		{
			name: "client secret with publishable key",
			input: "stripepaymentintent_token = '" + "pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" +
				"' and stripe_key = '" + "pk_live_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5abc123456" + "'",
			expectedPairs: []string{"pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" +
				"pk_live_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5abc123456"},
		},
		{
			name: "multiple client secrets with single key",
			input: `stripepaymentintent_token1 = '` + "pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" + `'
			stripepaymentintent_token2 = '` + "pi_4NuxCxMleJwHu7ix28a3tqPb_secret_ZsLKVLsjdcCkdH9IWig123456" + `'
			stripe_key = '` + "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" + `'`,
			expectedPairs: []string{
				"pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" +
					"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",
				"pi_4NuxCxMleJwHu7ix28a3tqPb_secret_ZsLKVLsjdcCkdH9IWig123456" +
					"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",
			},
		},
		{
			name: "single client secret with multiple keys",
			input: `stripepaymentintent_token = '` + "pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" + `'
			stripe_secret_key = '` + "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" + `'
			stripe_publishable_key = '` + "pk_live_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5abc123456" + `'`,
			expectedPairs: []string{
				"pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" +
					"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",
				"pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" +
					"pk_live_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5abc123456",
			},
		},
		{
			name: "multiple client secrets with multiple keys",
			input: `stripepaymentintent_token1 = '` + "pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" + `'
			stripepaymentintent_token2 = '` + "pi_4NuxCxMleJwHu7ix28a3tqPb_secret_ZsLKVLsjdcCkdH9IWig123456" + `'
			stripe_secret_key = '` + "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" + `'
			stripe_publishable_key = '` + "pk_live_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5abc123456" + `'`,
			expectedPairs: []string{
				"pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" +
					"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",
				"pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" +
					"pk_live_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5abc123456",
				"pi_4NuxCxMleJwHu7ix28a3tqPb_secret_ZsLKVLsjdcCkdH9IWig123456" +
					"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",
				"pi_4NuxCxMleJwHu7ix28a3tqPb_secret_ZsLKVLsjdcCkdH9IWig123456" +
					"pk_live_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5abc123456",
			},
		},
		{
			name:          "only client secret without keys",
			input:         "stripepaymentintent_token = '" + "pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" + "'",
			expectedPairs: []string{},
		},
		{
			name:          "only keys without client secret",
			input:         "stripe_key = '" + "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" + "'",
			expectedPairs: []string{},
		},
		{
			name: "invalid client secret with valid key",
			input: "stripepaymentintent_token = '" + "test_secret_test_1234567890abcdefg" + "' and stripe_key = '" +
				"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" + "'",
			expectedPairs: []string{},
		},
		{
			name: "mixed valid and invalid client secrets with key",
			input: `some_token = '` + "pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" + `'
			other_token = '` + "test_secret_test_1234567890abcdefg" + `'
			stripe_key = '` + "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" + `'`,
			expectedPairs: []string{"pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" +
				"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"},
		},
		{
			name: "complex scenario with multiple valid combinations",
			input: `
			# Multiple client secrets
			pi_token_1 = '` + "pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" + `'
			pi_token_2 = '` + "pi_4NuxCxMleJwHu7ix28a3tqPb_secret_ZsLKVLsjdcCkdH9IWig123456" + `'
			
			# Multiple secret keys
			secret_key_1 = '` + "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" + `'
			secret_key_2 = '` + "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" + `'
			
			# Multiple publishable keys  
			pub_key_1 = '` + "pk_live_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5abc123456" + `'
			pub_key_2 = '` + "pk_live_51NuxCxMleJwHu7ix0BItRxY7OXh9Gr8RLr6ZHGz8XHCrSGIeUeF9MgLdLaRl8oKw4y6ZKwoKZHHa2o4HzGeIK6abc123456" + `'`,
			expectedPairs: []string{
				"pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" +
					"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",
				"pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" +
					"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",
				"pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" +
					"pk_live_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5abc123456",
				"pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" +
					"pk_live_51NuxCxMleJwHu7ix0BItRxY7OXh9Gr8RLr6ZHGz8XHCrSGIeUeF9MgLdLaRl8oKw4y6ZKwoKZHHa2o4HzGeIK6abc123456",
				"pi_4NuxCxMleJwHu7ix28a3tqPb_secret_ZsLKVLsjdcCkdH9IWig123456" +
					"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",
				"pi_4NuxCxMleJwHu7ix28a3tqPb_secret_ZsLKVLsjdcCkdH9IWig123456" +
					"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",
				"pi_4NuxCxMleJwHu7ix28a3tqPb_secret_ZsLKVLsjdcCkdH9IWig123456" +
					"pk_live_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5abc123456",
				"pi_4NuxCxMleJwHu7ix28a3tqPb_secret_ZsLKVLsjdcCkdH9IWig123456" +
					"pk_live_51NuxCxMleJwHu7ix0BItRxY7OXh9Gr8RLr6ZHGz8XHCrSGIeUeF9MgLdLaRl8oKw4y6ZKwoKZHHa2o4HzGeIK6abc123456",
			},
		},
		{
			name: "test keys should not match (only live keys are detected)",
			input: `stripepaymentintent_token = '` + "pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456" + `'
			test_secret_key = 'sk_test_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5nJGydHjE'
			test_pub_key = 'pk_test_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5nJGydHjE'`,
			expectedPairs: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.expectedPairs) > 0 {
				if len(matchedDetectors) == 0 {
					t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
					return
				}
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.expectedPairs) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.expectedPairs), len(results))
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
			expected := make(map[string]struct{}, len(test.expectedPairs))
			for _, v := range test.expectedPairs {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}
