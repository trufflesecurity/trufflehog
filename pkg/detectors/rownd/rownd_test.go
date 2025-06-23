package rownd

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validKey      = "rvhpdb59-6ni1-60q3-jqng-orz5edgkq333"
	invalidKey    = "rvhpdb59?6ni1-60q3-jqng-orz5edgkq333"
	validSecret   = "uuzywot3x1nlfeogbyft1r9ojb234smw0fnmn7s8kj1s1cc1"
	invalidSecret = "uuzywot3x1nlfeogbyft1r9o?b234smw0fnmn7s8kj1s1cc1"
	validId       = "174079606475951818"
	invalidId     = "17?079606475951818"
	keyword       = "rownd"
)

func TestRownd_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword rownd",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n", keyword, validKey, keyword, validSecret, keyword, validId),
			want:  []string{validKey + validSecret},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n", keyword, invalidKey, keyword, invalidSecret, keyword, invalidId),
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
