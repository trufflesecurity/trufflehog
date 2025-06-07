package rechargepayments

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validApiKey      = "sk_test_3x3_2fbA8B8f75b3f74D3caEF6ec023c3AAbbe48Edcc2393dc343688Dfa8bbcb141f"
	invalidApiKey    = "sk_test_3x3_?fbA8B8f75b3f74D3caEF6ec023c3AAbbe48Edcc2393dc343688Dfa8bbcb141f"
	validOldApiSha   = "09ECafFABafCeDec29b51B425E1Ed5BC70c6C88c8CeddDe0ba7ab0Af"
	invalidOldApiSha = "0?ECafFABafCeDec29b51B425E1Ed5BC70c6C88c8CeddDe0ba7ab0Af"
	validOldApiMd5   = "FCd1AAaD6EF3D4bCFdaB9c831cBc0d57"
	invalidOldApiMd5 = "F?d1AAaD6EF3D4bCFdaB9c831cBc0d57"
	keyword          = "rechargepayments"
)

func TestRechargePayments_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword rechargepayments",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n", keyword, validApiKey, keyword, validOldApiSha, keyword, validOldApiMd5),
			want:  []string{validApiKey, validOldApiSha, validOldApiMd5},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n", keyword, invalidApiKey, keyword, invalidOldApiSha, keyword, invalidOldApiMd5),
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
