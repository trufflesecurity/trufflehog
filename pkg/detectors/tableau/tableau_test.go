package tableau

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPATName     = "test-token-6"
	validPATSecret   = "YMqNfVWiTSa0QgpoJ9GpCw==:KTamjuKrXF5gVETjIJafBBvP8Ctj5aJ3"
	invalidPATSecret = "invalid-secret-format"
	// Tableau Online endpoints for testing
	validTableauURL    = "prod-ansouthgest-a.online.tableau.com"
	valid2ndTableauURL = "prod.online.tableau.com"
	invalidTableauURL  = "prod.tabeau.com"
)

func TestTableau_Pattern(t *testing.T) {
	d := Scanner{}
	d.UseFoundEndpoints(true) // Enable found endpoints for tests
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name        string
		input       string
		want        []string
		description string
	}{
		{
			name:        "tableau_prefix_with_token_name",
			input:       fmt.Sprintf("token=%s\nsecret=%s\nserver=%s", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests tableau prefix directly followed by token name",
		},
		{
			name:        "pat_prefix_with_name",
			input:       fmt.Sprintf("pat %s\n%s\nurl=%s", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests pat prefix triggering detection",
		},
		{
			name:        "name_prefix_with_token",
			input:       fmt.Sprintf("name %s\n%s\nurl=%s", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests name prefix triggering detection",
		},
		{
			name:  "single_token_multiple_urls",
			input: fmt.Sprintf("token %s\n%s\nserver1=%s\nserver2=%s", validPATName, validPATSecret, validTableauURL, valid2ndTableauURL),
			want: []string{
				fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL),
				fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, valid2ndTableauURL),
			},
			description: "Tests single token with multiple URLs",
		},
		{
			name:        "invalid_secret_format",
			input:       fmt.Sprintf("tableau %s\n%s\nserver=%s", validPATName, invalidPATSecret, validTableauURL),
			want:        []string{},
			description: "Tests that invalid secret format is not detected",
		},
		{
			name:        "invalid_tableau_url",
			input:       fmt.Sprintf("tableau %s\n%s\nserver=%s", validPATName, validPATSecret, invalidTableauURL),
			want:        []string{},
			description: "Tests that invalid Tableau URL is not detected when useFoundEndpoints is true",
		},
		{
			name:        "missing_token_name",
			input:       fmt.Sprintf("\n%s\nserver=%s", validPATSecret, validTableauURL),
			want:        []string{},
			description: "Tests that missing token name produces no results",
		},
		{
			name:        "missing_secret",
			input:       fmt.Sprintf("tableau %s\nserver=%s", validPATName, validTableauURL),
			want:        []string{},
			description: "Tests that missing secret produces no results",
		},
		{
			name:        "no_tableau_keywords",
			input:       "username=test\npassword=secret123\nhost=example.com",
			want:        []string{},
			description: "Tests that non-Tableau config produces no results",
		},
		{
			name:        "token_name_with_whitespace",
			input:       fmt.Sprintf("name   %s\n%s\nserver=%s", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests token name with extra whitespace",
		},
		{
			name:        "pat_with_single_quotes",
			input:       fmt.Sprintf("pat '%s'\n%s\nserver=%s", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests token name with single quotes",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 {
				if len(matchedDetectors) == 0 {
					t.Errorf("keywords '%v' not matched in input: %s", d.Keywords(), test.input)
					return
				}
			}

			if len(matchedDetectors) == 0 && len(test.want) == 0 {
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("FromData error: %v", err)
				return
			}

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
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
