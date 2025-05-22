package stripepaymentintent

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

var (
	validClientSecret          = "pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456"
	anotherValidClientSecret   = "pi_4NuxCxMleJwHu7ix28a3tqPb_secret_ZsLKVLsjdcCkdH9IWig123456"
	invalidClientSecret        = "test_secret_test_1234567890abcdefg"
	validSecretKey             = "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"
	anotherValidSecretKey      = "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"
	validPublishableKey        = "pk_live_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5abc123456"
	anotherValidPublishableKey = "pk_live_51NuxCxMleJwHu7ix0BItRxY7OXh9Gr8RLr6ZHGz8XHCrSGIeUeF9MgLdLaRl8oKw4y6ZKwoKZHHa2o4HzGeIK6abc123456"
)

func TestStripepaymentintent_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name            string
		input           string
		wantResultCount int
		expectedPairs   []string
	}{
		{
			name:            "client secret with secret key",
			input:           "stripepaymentintent_token = '" + validClientSecret + "' and stripe_key = '" + validSecretKey + "'",
			wantResultCount: 1,
			expectedPairs:   []string{validClientSecret},
		},
		{
			name:            "client secret with publishable key",
			input:           "stripepaymentintent_token = '" + validClientSecret + "' and stripe_key = '" + validPublishableKey + "'",
			wantResultCount: 1,
			expectedPairs:   []string{validClientSecret},
		},
		{
			name: "multiple client secrets with single key",
			input: `stripepaymentintent_token1 = '` + validClientSecret + `'
			stripepaymentintent_token2 = '` + anotherValidClientSecret + `'
			stripe_key = '` + validSecretKey + `'`,
			wantResultCount: 2,
			expectedPairs:   []string{validClientSecret, anotherValidClientSecret},
		},
		{
			name: "single client secret with multiple keys",
			input: `stripepaymentintent_token = '` + validClientSecret + `'
			stripe_secret_key = '` + validSecretKey + `'
			stripe_publishable_key = '` + validPublishableKey + `'`,
			wantResultCount: 2,
			expectedPairs:   []string{validClientSecret, validClientSecret},
		},
		{
			name: "multiple client secrets with multiple keys",
			input: `stripepaymentintent_token1 = '` + validClientSecret + `'
			stripepaymentintent_token2 = '` + anotherValidClientSecret + `'
			stripe_secret_key = '` + validSecretKey + `'
			stripe_publishable_key = '` + validPublishableKey + `'`,
			wantResultCount: 4, // 2 client secrets × 2 keys = 4 results
			expectedPairs:   []string{validClientSecret, validClientSecret, anotherValidClientSecret, anotherValidClientSecret},
		},
		{
			name:            "only client secret without keys",
			input:           "stripepaymentintent_token = '" + validClientSecret + "'",
			wantResultCount: 0,
			expectedPairs:   []string{},
		},
		{
			name:            "only keys without client secret",
			input:           "stripe_key = '" + validSecretKey + "'",
			wantResultCount: 0,
			expectedPairs:   []string{},
		},
		{
			name:            "invalid client secret with valid key",
			input:           "stripepaymentintent_token = '" + invalidClientSecret + "' and stripe_key = '" + validSecretKey + "'",
			wantResultCount: 0,
			expectedPairs:   []string{},
		},
		{
			name: "mixed valid and invalid client secrets with key",
			input: `some_token = '` + validClientSecret + `'
			other_token = '` + invalidClientSecret + `'
			stripe_key = '` + validSecretKey + `'`,
			wantResultCount: 1,
			expectedPairs:   []string{validClientSecret},
		},
		{
			name: "complex scenario with multiple valid combinations",
			input: `
			# Multiple client secrets
			pi_token_1 = '` + validClientSecret + `'
			pi_token_2 = '` + anotherValidClientSecret + `'
			
			# Multiple secret keys
			secret_key_1 = '` + validSecretKey + `'
			secret_key_2 = '` + anotherValidSecretKey + `'
			
			# Multiple publishable keys  
			pub_key_1 = '` + validPublishableKey + `'
			pub_key_2 = '` + anotherValidPublishableKey + `'`,
			wantResultCount: 8, // 2 client secrets × 4 keys = 8 results
			expectedPairs: []string{
				validClientSecret, validClientSecret, validClientSecret, validClientSecret,
				anotherValidClientSecret, anotherValidClientSecret, anotherValidClientSecret, anotherValidClientSecret,
			},
		},
		{
			name: "test keys should not match (only live keys are detected)",
			input: `stripepaymentintent_token = '` + validClientSecret + `'
			test_secret_key = 'sk_test_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5nJGydHjE'
			test_pub_key = 'pk_test_51MtwBwLkdIwHu7ix0AHtQwX6NWg8Fq7QKq5YGFy7WGBqRFHdTdE8LfKcKzQk7nJv3x5YJvnJYGGz1n3GyFdHJ5nJGydHjE'`,
			wantResultCount: 0,
			expectedPairs:   []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))

			if test.wantResultCount > 0 {
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

			if len(results) != test.wantResultCount {
				t.Errorf("expected %d results, got %d", test.wantResultCount, len(results))
				t.Errorf("Input: %s", test.input)
				for i, r := range results {
					t.Errorf("Result %d: Raw=%s, RawV2=%s", i, string(r.Raw), string(r.RawV2))
				}
				return
			}

			if test.wantResultCount == 0 {
				return
			}

			actualClientSecrets := make([]string, len(results))
			for i, r := range results {
				if len(r.Raw) == 0 {
					t.Errorf("result %d missing Raw field", i)
					continue
				}
				actualClientSecrets[i] = string(r.Raw)

				if len(r.RawV2) == 0 {
					t.Errorf("result %d missing RawV2 field", i)
					continue
				}

				if len(r.RawV2) <= len(r.Raw) {
					t.Errorf("result %d RawV2 should contain Raw + key, but RawV2 length (%d) <= Raw length (%d)",
						i, len(r.RawV2), len(r.Raw))
				}

				if r.DetectorType != detectorspb.DetectorType_StripePaymentIntent {
					t.Errorf("result %d has wrong DetectorType: %v", i, r.DetectorType)
				}
			}

			if diff := cmp.Diff(test.expectedPairs, actualClientSecrets, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
				t.Errorf("%s client secret diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}
