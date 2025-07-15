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
		{
			name:        "tableau_keyword_with_token_name",
			input:       fmt.Sprintf("tableau_token_name=%s\nsecret=%s\nserver=%s", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests tableau keyword with token_name pattern",
		},
		{
			name:        "tableau_online_url_with_credentials",
			input:       fmt.Sprintf("Tableau Connect to %s\ntoken_name=%s\n%s", validTableauURL, validPATName, validPATSecret),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests tableau online URL triggering detection",
		},
		{
			name:        "tableau_context_with_credentials",
			input:       fmt.Sprintf("tableau_name=%s\n%s\nurl=%s", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests tableau context triggering detection",
		},
		{
			name:  "multiple_token_names_with_tableau_context",
			input: fmt.Sprintf("tableau_token_name=%s\ntoken_name=%s\n%s\nserver=%s", validPATName, "another-token", validPATSecret, validTableauURL),
			want: []string{
				fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL),
				fmt.Sprintf("%s:%s:%s", "another-token", validPATSecret, validTableauURL),
			},
			description: "Tests multiple token names with tableau context",
		},
		{
			name:  "single_token_multiple_urls_with_context",
			input: fmt.Sprintf("token_name=%s\n%s\nserver1=%s\nserver2=%s", validPATName, validPATSecret, validTableauURL, valid2ndTableauURL),
			want: []string{
				fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL),
				fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, valid2ndTableauURL),
			},
			description: "Tests single token with multiple URLs and tableau context",
		},
		{
			name:        "invalid_secret_format_with_tableau_keyword",
			input:       fmt.Sprintf("tableau_token_name=%s\n%s\nserver=%s", validPATName, invalidPATSecret, validTableauURL),
			want:        []string{},
			description: "Tests that invalid secret format is not detected even with keywords",
		},
		{
			name:        "invalid_tableau_url_with_keyword",
			input:       fmt.Sprintf("tableau_token_name=%s\n%s\nserver=%s", validPATName, validPATSecret, invalidTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, "prod-ansouthgest-a.online.tableau.com")}, // Uses default endpoint
			description: "Tests that invalid Tableau URL uses default endpoint",
		},
		{
			name:        "missing_token_name_with_tableau_context",
			input:       fmt.Sprintf("tableau_secret=%s\nserver=%s", validPATSecret, validTableauURL),
			want:        []string{},
			description: "Tests that missing token name produces no results even with tableau keyword",
		},
		{
			name:        "missing_secret_with_tableau_context",
			input:       fmt.Sprintf("tableau_token_name=%s\nserver=%s", validPATName, validTableauURL),
			want:        []string{},
			description: "Tests that missing secret produces no results even with tableau keyword",
		},
		{
			name:        "no_tableau_keywords",
			input:       "username=test\npassword=secret123\nhost=example.com",
			want:        []string{},
			description: "Tests that non-Tableau config produces no results",
		},
		{
			name:        "quoted_token_name_with_whitespace",
			input:       fmt.Sprintf("tableau_token_name = \"%s\" \n%s\nserver = %s", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests token name with quotes and extra whitespace",
		},
		{
			name:        "simple_token_name_format",
			input:       fmt.Sprintf("name=%s\n%s\nserver=%s", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests simple name= format",
		},
		{
			name:        "token_name_with_colon",
			input:       fmt.Sprintf("token_name: %s\n%s\nserver: %s", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests token name with colon separator",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Debug: Check if keywords are found
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			
			if len(test.want) > 0 {
				if len(matchedDetectors) == 0 {
					t.Errorf("keywords '%v' not matched in input: %s", d.Keywords(), test.input)
					return
				}
				t.Logf("Keywords matched: %d detectors found", len(matchedDetectors))
			}

			if len(matchedDetectors) == 0 && len(test.want) == 0 {
				t.Logf("No keywords matched and no results expected - PASS")
				return
			}

			// Debug: Test the extraction functions directly
			tokenNames := extractTokenNames(test.input)
			tokenSecrets := extractTokenSecrets(test.input)
			foundURLs := extractTableauURLs(test.input)
			
			t.Logf("Extracted token names: %v", tokenNames)
			t.Logf("Extracted token secrets: %v", tokenSecrets)
			t.Logf("Extracted URLs: %v", foundURLs)

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("FromData error: %v", err)
				return
			}

			t.Logf("Results found: %d", len(results))
			for i, result := range results {
				t.Logf("Result %d: %s", i, string(result.RawV2))
			}

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
				for _, r := range results {
					t.Logf("Got result: %s", string(r.RawV2))
				}
				for _, w := range test.want {
					t.Logf("Expected: %s", w)
				}
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

// Test the individual extraction functions
func TestExtractionFunctions(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName []string
		wantSecret []string
		wantURL  []string
	}{
		{
			name:       "basic_extraction",
			input:      fmt.Sprintf("tableau_token_name=%s\n%s\nserver=%s", validPATName, validPATSecret, validTableauURL),
			wantName:   []string{validPATName},
			wantSecret: []string{validPATSecret},
			wantURL:    []string{validTableauURL},
		},
		{
			name:       "multiple_names",
			input:      fmt.Sprintf("name=%s\ntoken_name=%s\n%s", validPATName, "another-token", validPATSecret),
			wantName:   []string{validPATName, "another-token"},
			wantSecret: []string{validPATSecret},
			wantURL:    []string{},
		},
		{
			name:       "no_matches",
			input:      "username=test\npassword=secret123",
			wantName:   []string{},
			wantSecret: []string{},
			wantURL:    []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			names := extractTokenNames(test.input)
			secrets := extractTokenSecrets(test.input)
			urls := extractTableauURLs(test.input)

			if diff := cmp.Diff(test.wantName, names); diff != "" {
				t.Errorf("token names diff: (-want +got)\n%s", diff)
			}
			if diff := cmp.Diff(test.wantSecret, secrets); diff != "" {
				t.Errorf("token secrets diff: (-want +got)\n%s", diff)
			}
			if diff := cmp.Diff(test.wantURL, urls); diff != "" {
				t.Errorf("URLs diff: (-want +got)\n%s", diff)
			}
		})
	}
}