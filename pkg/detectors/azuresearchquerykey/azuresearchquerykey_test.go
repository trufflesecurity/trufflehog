package azuresearchquerykey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `
	azure:
		azure_url: https://tzyexx2ktdfhha8w1cktqzbrgv37ywtu.search.windows.net/indexes/n81wg81jogjfq93cyxfi67vy2g7vwlcqfgi
		azure_key: OKalbM5EBt5hloqU46phTUCZqvNAlZ4S2Jd2gFUCOQ3HG0vQ2uEp

	`
	invalidPattern = `
	azure:
		url: http://invalid.azurecr.io.azure.com
		azure_key: BXIMbhBlC3=5hIbqCEKvq7op!V2ZfO0XWbcnasZmPm/AJfQqdcnt/+2Ytxc1hDq1m/
	`
)

func TestAzureSearchQueryKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: validPattern,
			want:  []string{"OKalbM5EBt5hloqU46phTUCZqvNAlZ4S2Jd2gFUCOQ3HG0vQ2uEphttps://tzyexx2ktdfhha8w1cktqzbrgv37ywtu.search.windows.net/indexes/n81wg81jogjfq93cyxfi67vy2g7vwlcqfgi"},
		},
		{
			name:  "invalid pattern",
			input: invalidPattern,
			want:  nil,
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
