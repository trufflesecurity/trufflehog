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
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name        string
		input       string
		want        []string
		description string
	}{
		// Basic valid patterns - keywords must be present for PrefixRegex to work
		{
			name:        "tableau_keyword_with_token_name",
			input:       fmt.Sprintf("# Tableau configuration tableau_token_name = %s secret = %s server = %s", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests tableau keyword with token_name pattern",
		},
		{
			name:        "tableau_online_url_with_credentials",
			input:       fmt.Sprintf(" Tableau Connect to %s\ntoken_name = %s\nsecret = %s", validTableauURL, validPATName, validPATSecret),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests tableau online URL triggering detection",
		},
		{
			name:        "tableau_config_multiple_formats",
			input:       fmt.Sprintf("# Tableau server config\npat_name = %s\ntoken_secret = %s\ntableau_server = %s", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests tableau keyword with pat_name pattern",
		},

		// Test secret pattern matching with context
		{
			name:        "tableau_context_with_credentials",
			input:       fmt.Sprintf("# Connecting to Tableau\nname = %s\nsecret = %s\nurl = %s", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests tableau context triggering detection",
		},

		// Multiple combinations with keywords
		{
			name:  "multiple_token_names_with_tableau_context",
			input: fmt.Sprintf("# Tableau server configuration\ntableau_token_name = %s\ntoken_name = %s\nsecret = %s\nserver = %s", validPATName, "another-token", validPATSecret, validTableauURL),
			want: []string{
				fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL),
				fmt.Sprintf("%s:%s:%s", "another-token", validPATSecret, validTableauURL),
			},
			description: "Tests multiple token names with tableau context",
		},
		{
			name:  "single_token_multiple_urls_with_context",
			input: fmt.Sprintf("# Tableau online config\ntoken_name = %s\nsecret = %s\nserver1 = %s\nserver2 = %s", validPATName, validPATSecret, validTableauURL, valid2ndTableauURL),
			want: []string{
				fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL),
				fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, valid2ndTableauURL),
			},
			description: "Tests single token with multiple URLs and tableau context",
		},
		{
			name:        "invalid_secret_format_with_tableau_keyword",
			input:       fmt.Sprintf("# Tableau config\ntoken_name = %s\nsecret = %s\nserver = %s", validPATName, invalidPATSecret, validTableauURL),
			want:        []string{},
			description: "Tests that invalid secret format is not detected even with keywords",
		},
		{
			name:        "invalid_tableau_url_with_keyword",
			input:       fmt.Sprintf("# Tableau setup\ntoken_name = %s\nsecret = %s\nserver = %s", validPATName, validPATSecret, invalidTableauURL),
			want:        []string{},
			description: "Tests that invalid Tableau URL is not detected even with keywords",
		},

		// Missing components with keywords
		{
			name:        "missing_token_name_with_tableau_context",
			input:       fmt.Sprintf("# Tableau server\nsecret = %s\nserver = %s", validPATSecret, validTableauURL),
			want:        []string{},
			description: "Tests that missing token name produces no results even with tableau keyword",
		},
		{
			name:        "missing_secret_with_tableau_context",
			input:       fmt.Sprintf("# Tableau configuration\ntoken_name = %s\nserver = %s", validPATName, validTableauURL),
			want:        []string{},
			description: "Tests that missing secret produces no results even with tableau keyword",
		},
		{
			name:        "no_tableau_keywords",
			input:       "username = test\npassword = secret123\nhost = example.com",
			want:        []string{},
			description: "Tests that non-Tableau config produces no results",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(test.want) == 0 {
					if len(results) != 0 {
						t.Errorf("expected no results but got %d", len(results))
					}
				} else {
					t.Errorf("expected %d results, got %d", len(test.want), len(results))
				}
				return
			}

			if len(test.want) == 0 {
				return // Test passed - no results expected and none received
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
