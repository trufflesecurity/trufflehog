package saucelabs

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validUsername   = "nBpeh2YF3tjMNmKAUHrDpfXJZJ.ZUhWmObRC735zdh99LeJh4Kcr_2"
	invalidUsername = "?Bpeh?YF3tjMNmKAUHrDpfXJZJ.ZUhWmObRC735zdh99LeJh4Kcr_2"
	validKey        = "9toqmh6r-g2ly-k3fr-fiyr-5jnnewlxy3u9"
	invalidKey      = "9toqmh6r?g2ly-k3fr-fiyr-5jnnewlxy3u9"
	validBaseUrl    = "api.eu-west-0,saucelabs.com"
	invalidBaseUrl  = "?pi.eu-west-0,saucelabs.co?"
	keyword         = "saucelabs"
)

func TestSauceLabs_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword saucelabs",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n", keyword, validUsername, keyword, validKey, keyword, validBaseUrl),
			want:  []string{".com" + validKey, "token" + validKey},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n", keyword, invalidUsername, keyword, invalidKey, keyword, invalidBaseUrl),
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
