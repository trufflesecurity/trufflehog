package teamgate

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
    validToken   = "78fohntospcdns4n7zokz7zr134vn7ua7io7ehp1"
    invalidToken = "78fohntospcdns4n7?okz7zr134vn7ua7io7ehp1"
    validKey     = "AdPZhlbr8bIaIUomTizYvauT2HMNUfm6oK4Aft8JICXKvdKbHOEeRVLPycmGLi60QBksu5tPvD8X4ciX"
    invalidKey   = "AdPZhlbr8b?aIUomTizYvauT2HMNUfm6oK4Aft8JICXKvdKbHOEeRVLPycmGLi60QBksu5tPvD8X4ciX"
    keyword      = "teamgate"
)

func TestTeamgate_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword teamgate",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validToken, keyword, validKey),
			want:  []string{validToken},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, invalidToken, keyword, invalidKey),
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
