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
	invalidTableauURL  = "prod.tabeau.com" // missing .online
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
		// Basic valid patterns - different formats
		{
			name:        "config_style_with_equals",
			input:       fmt.Sprintf("personalAccessTokenName = '%s'\npersonalAccessTokenSecret = '%s'\nserver = '%s'", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests basic config-style key=value format",
		},
		{
			name:        "config_style_with_colon",
			input:       fmt.Sprintf("token_name: '%s'\ntoken_secret: '%s'\nendpoint: '%s'", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests YAML-style key: value format",
		},
		{
			name:        "json_format",
			input:       fmt.Sprintf(`{"personalAccessTokenName": "%s", "personalAccessTokenSecret": "%s", "server": "%s"}`, validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests JSON object format",
		},
		{
			name:        "unquoted_values",
			input:       fmt.Sprintf("access_token_name = %s\naccess_token_secret = %s\nserver = %s", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests unquoted configuration values",
		},

		// Abbreviation patterns
		{
			name:        "pat_abbreviation",
			input:       fmt.Sprintf("pat_name = '%s'\npat_secret = '%s'\ntableau_server = '%s'", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests PAT abbreviation format",
		},
		{
			name:        "api_token_variant",
			input:       fmt.Sprintf("api_token_name = '%s'\napi_token_secret = '%s'\nhost = '%s'", validPATName, validPATSecret, validTableauURL),
			want:        []string{fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL)},
			description: "Tests API token naming variant",
		},

		// Multiple combinations
		{
			name:  "multiple_token_names_single_secret",
			input: fmt.Sprintf("pat_name = '%s'\ntoken_name = '%s'\npat_secret = '%s'\nserver = '%s'", validPATName, "another-token", validPATSecret, validTableauURL),
			want: []string{
				fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL),
				fmt.Sprintf("%s:%s:%s", "another-token", validPATSecret, validTableauURL),
			},
			description: "Tests multiple token names with single secret",
		},
		{
			name:  "single_token_multiple_urls",
			input: fmt.Sprintf("pat_name = '%s'\npat_secret = '%s'\nserver1 = '%s'\nserver2 = '%s'", validPATName, validPATSecret, validTableauURL, valid2ndTableauURL),
			want: []string{
				fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, validTableauURL),
				fmt.Sprintf("%s:%s:%s", validPATName, validPATSecret, valid2ndTableauURL),
			},
			description: "Tests single token with multiple URLs",
		},
		{
			name:        "invalid_secret_format",
			input:       fmt.Sprintf("pat_name = '%s'\npat_secret = '%s'\nserver = '%s'", validPATName, invalidPATSecret, validTableauURL),
			want:        []string{},
			description: "Tests rejection of invalid secret format",
		},
		{
			name:        "invalid_tableau_url",
			input:       fmt.Sprintf("pat_name = '%s'\npat_secret = '%s'\nserver = '%s'", validPATName, validPATSecret, invalidTableauURL),
			want:        []string{},
			description: "Tests rejection of invalid Tableau URL format",
		},
		{
			name:        "missing_token_name",
			input:       fmt.Sprintf("pat_secret = '%s'\nserver = '%s'", validPATSecret, validTableauURL),
			want:        []string{},
			description: "Tests that missing token name produces no results",
		},
		{
			name:        "missing_secret",
			input:       fmt.Sprintf("pat_name = '%s'\nserver = '%s'", validPATName, validTableauURL),
			want:        []string{},
			description: "Tests that missing secret produces no results",
		},
		{
			name:        "no_tableau_keywords",
			input:       "username = 'test'\npassword = 'secret123'\nhost = 'example.com'",
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
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
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