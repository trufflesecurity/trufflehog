package hasura

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestHasura_Pattern(t *testing.T) {
	d := Scanner{}

	tests := []struct {
		name          string
		input         string
		expectedPairs []string
	}{
		{
			name:          "simple case: one domain, one key",
			input:         "The hasura admin secret is 05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4 for the domain project-one-12345.hasura.app",
			expectedPairs: []string{"project-one-12345.hasura.app:05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4"},
		},
		{
			name: "multiple keys, single domain",
			input: `
				The domain is project-one-12345.hasura.app
				hasura key1: 05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4
				hasura key2: aBcDeFgHiJkLmNoPqRsTuVwXyZ123456aBcDeFgHiJkLmNoPqRsTuVwXyZ123456
			`,
			expectedPairs: []string{
				"project-one-12345.hasura.app:05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4",
				"project-one-12345.hasura.app:aBcDeFgHiJkLmNoPqRsTuVwXyZ123456aBcDeFgHiJkLmNoPqRsTuVwXyZ123456",
			},
		},
		{
			name: "single key, multiple domains",
			input: `
				The hasura key is 05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4
				Domain 1: project-one-12345.hasura.app
				Domain 2: project-two-67890.hasura.app
			`,
			expectedPairs: []string{
				"project-one-12345.hasura.app:05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4",
				"project-two-67890.hasura.app:05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4",
			},
		},
		{
			name: "many-to-many: multiple keys and domains",
			input: `
				Here is a hasura key: 05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4
				And another hasura key: aBcDeFgHiJkLmNoPqRsTuVwXyZ123456aBcDeFgHiJkLmNoPqRsTuVwXyZ123456
				And a hasura domain: project-one-12345.hasura.app
				And another domain: project-two-67890.hasura.app
			`,
			expectedPairs: []string{
				"project-one-12345.hasura.app:05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4",
				"project-one-12345.hasura.app:aBcDeFgHiJkLmNoPqRsTuVwXyZ123456aBcDeFgHiJkLmNoPqRsTuVwXyZ123456",
				"project-two-67890.hasura.app:05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4",
				"project-two-67890.hasura.app:aBcDeFgHiJkLmNoPqRsTuVwXyZ123456aBcDeFgHiJkLmNoPqRsTuVwXyZ123456",
			},
		},
		{
			name:          "negative case: only a key, no domain",
			input:         "A hasura secret without a domain: 05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4",
			expectedPairs: []string{},
		},
		{
			name:          "negative case: only a domain, no key",
			input:         "A hasura domain without a secret: project-one-12345.hasura.app",
			expectedPairs: []string{},
		},
		{
			name:          "negative case: invalid key with valid domain",
			input:         "An invalid hasura key not-a-valid-key-12345 with a valid domain project-one-12345.hasura.app",
			expectedPairs: []string{},
		},
		{
			name: "mixed valid and invalid keys with one domain",
			input: `
				The domain is project-one-12345.hasura.app
				Valid hasura key: 05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4
				Invalid hasura key: not-a-valid-key-12345
			`,
			expectedPairs: []string{"project-one-12345.hasura.app:05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4"},
		},
		{
			name:          "negative case: invalid domain with valid key",
			input:         "A hasura key 05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4 with an invalid domain example.com",
			expectedPairs: []string{},
		},
		{
			name:          "negative case: key without 'hasura' keyword nearby",
			input:         "A random 64-char string 05tUFwoJfK2dui0CWKxzqJHmNzQrsX40Kwd7g2OEqLl1RZeU6pRvyOSnD4nghgH4 with a valid domain project-one-12345.hasura.app",
			expectedPairs: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Run the detector with verification turned off for pattern testing.
			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Fatalf("FromData() returned an unexpected error: %v", err)
			}

			// Check if the number of results matches what we expect.
			if len(results) != len(test.expectedPairs) {
				t.Errorf("expected %d results, but got %d", len(test.expectedPairs), len(results))
				// Log results for easier debugging
				for i, r := range results {
					t.Logf("Got result %d: %s", i, string(r.RawV2))
				}
				t.FailNow()
			}

			// For a more robust comparison, load the results into maps to ignore order.
			actualPairs := make(map[string]struct{}, len(results))
			for _, r := range results {
				// The RawV2 field should contain the "domain:key" pair.
				if len(r.RawV2) > 0 {
					actualPairs[string(r.RawV2)] = struct{}{}
				}
			}

			expectedPairsMap := make(map[string]struct{}, len(test.expectedPairs))
			for _, v := range test.expectedPairs {
				expectedPairsMap[v] = struct{}{}
			}

			// Use cmp.Diff to find any mismatches between the expected and actual pairs.
			if diff := cmp.Diff(expectedPairsMap, actualPairs); diff != "" {
				t.Errorf("FromData() results mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
