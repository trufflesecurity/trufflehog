package azure_cosmosdb

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestCosmosDB_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid document db pattern",
			input: `
				Cluster name: Cluster name must be at least 3 characters and at most 40 characters.
				Cluster name must only contain lowercase letters, numbers, and hyphens.
				The cluster name must not start or end in a hyphen.
				// config
				cosmosKey: FakeeP35zYGPXaEUfakeU7S8kcOY7NI7id8ddbHfakeAifake8Bbql1mXhMF2t0wQ0FAKEPQrwZZACDb3msoAg==
				https://trufflesecurity-fake.documents.azure.com:443`,
			want: []string{fmt.Sprintf("key: %s account_url: %s", "FakeeP35zYGPXaEUfakeU7S8kcOY7NI7id8ddbHfakeAifake8Bbql1mXhMF2t0wQ0FAKEPQrwZZACDb3msoAg==", "trufflesecurity-fake.documents.azure.com")},
		},
		{
			name: "valid table db pattern",
			input: `
				Cluster name: Cluster name must be at least 3 characters and at most 40 characters.
				Cluster name must only contain lowercase letters, numbers, and hyphens.
				The cluster name must not start or end in a hyphen.
				// config
				cosmosKey: FakeeP35zYGPXaEUfakeU7S8kcOY7NI7id8ddbHfakeAifake8Bbql1mXhMF2t0wQ0FAKEPQrwZZACDb3msoAg==
				https://trufflesecurity-fake.table.cosmos.azure.com:443`,
			want: []string{fmt.Sprintf("key: %s account_url: %s", "FakeeP35zYGPXaEUfakeU7S8kcOY7NI7id8ddbHfakeAifake8Bbql1mXhMF2t0wQ0FAKEPQrwZZACDb3msoAg==", "trufflesecurity-fake.table.cosmos.azure.com")},
		},
		{
			name: "invalid pattern",
			input: `
				FakeeP35zYGPXaEUfakeU7S8kcOY7I7id8ddbHfakeAifake8Bbql1mXhMF2t0wQ0FAKEPQrwZZACDb3msoAg==
				https://not-a-host.documents.azure.com:443`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
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
