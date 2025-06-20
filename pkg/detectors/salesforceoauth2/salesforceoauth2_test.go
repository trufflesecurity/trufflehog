package salesforceoauth2

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestSalesforceOauth2_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "simple case: one of each component",
			input: `
				salesforce_domain = "my-test-org-123.my.salesforce.com"
				salesforce_key = "3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54El.Wkce6JTB1LmsxhzVaaa.VZ7"
				salesforce_secret = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"
			`,
			want: []string{
				"my-test-org-123.my.salesforce.com:3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54El.Wkce6JTB1LmsxhzVaaa.VZ7:A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
			},
		},
		{
			name: "combinatorial test: multiple keys, one domain and secret",
			input: `
				salesforce_domain = "my-test-org-123.my.salesforce.com"
				salesforce_key1 = "3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54El.Wkce6JTB1LmsxhzVaaa.VZ7"
				salesforce_key2 = "3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54ElfWkce6JTB1LmsxhzVaaaaVZ8"
				salesforce_secret = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"
			`,
			want: []string{
				"my-test-org-123.my.salesforce.com:3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54El.Wkce6JTB1LmsxhzVaaa.VZ7:A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
				"my-test-org-123.my.salesforce.com:3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54ElfWkce6JTB1LmsxhzVaaaaVZ8:A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
			},
		},
		{
			name: "combinatorial test: two domains, two keys, one secret",
			input: `
				salesforce_domain1 = "my-test-org-123.my.salesforce.com"
				salesforce_domain2 = "another-dev-org.my.salesforce.com"
				salesforce_key1 = "3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54El.Wkce6JTB1LmsxhzVaaa.VZ7"
				salesforce_key2 = "3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54ElfWkce6JTB1LmsxhzVaaaaVZ8"
				salesforce_secret = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"
			`,
			want: []string{
				"my-test-org-123.my.salesforce.com:3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54El.Wkce6JTB1LmsxhzVaaa.VZ7:A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
				"my-test-org-123.my.salesforce.com:3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54ElfWkce6JTB1LmsxhzVaaaaVZ8:A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
				"another-dev-org.my.salesforce.com:3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54El.Wkce6JTB1LmsxhzVaaa.VZ7:A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
				"another-dev-org.my.salesforce.com:3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54ElfWkce6JTB1LmsxhzVaaaaVZ8:A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
			},
		},
		{
			name:  "negative case: missing secret component",
			input: `salesforce_domain = "my-test-org-123.my.salesforce.com", salesforce_key = "3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54El.Wkce6JTB1LmsxhzVaaa.VZ7"`,
			want:  []string{},
		},
		{
			name:  "negative case: invalid key format",
			input: `salesforce_domain = "my-test-org-123.my.salesforce.com", salesforce_key = "invalid-key-format", salesforce_secret = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"`,
			want:  []string{},
		},
		{
			name:  "negative case: invalid secret format (too short)",
			input: `salesforce_domain = "my-test-org-123.my.salesforce.com", salesforce_key = "3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54El.Wkce6JTB1LmsxhzVaaa.VZ7", salesforce_secret = "ABCDEFG"`,
			want:  []string{},
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
