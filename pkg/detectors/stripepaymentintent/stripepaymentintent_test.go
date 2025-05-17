package stripepaymentintent

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validClientSecret        = "pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhfZluoGH"
	anotherValidClientSecret = "pi_4NuxCxMleJwHu7ix28a3tqPa_secret_YsKJUKrjbcBjcG8HVhfZlabGH"
	invalidClientSecret      = "pi_3MtwBwLkdIwHu7ix28a3tqPa"
)

func TestStripepaymentintent_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "single valid client secret",
			input: "stripepaymentintent_token = '" + validClientSecret + "'",
			want:  []string{validClientSecret},
		},
		{
			name: "multiple valid client secrets",
			input: `stripepaymentintent_token1 = '` + validClientSecret + `'
	stripepaymentintent_token2 = '` + anotherValidClientSecret + `'`,
			want: []string{validClientSecret, anotherValidClientSecret},
		},
		{
			name:  "only invalid client secret",
			input: "stripepaymentintent_token = '" + invalidClientSecret + "'",
			want:  []string{},
		},
		{
			name: "mixed valid and invalid client secrets",
			input: `some_token = '` + validClientSecret + `'
	other_token = '` + invalidClientSecret + `'`,
			want: []string{validClientSecret},
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
