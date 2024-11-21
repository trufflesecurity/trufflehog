package portainer

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validEndpoint   = "http://>xC'w//b7U@CtF|>|Fqw'2Z"
	invalidEndpoint = "?ttp://>xC'w//b7U@CtF|>|Fqw'2?"
	validToken      = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.EHHJE6Aht7Exhje8rUMLScr2bxcoTvWBl9bjMYZhCMYMLPD3EpUZL9SNd839DcI95lYtMfclPffpFrrJ0BbgryxnrfUSeeSKHu.W9Ur5_DLIBpXO3mfh404_7Kt9o8XZRnLTLyam2fdhB_"
	invalidToken    = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.EHHJE6Aht7Exhje8rUM?Scr2bxcoTvWBl9bjMYZhCMYMLPD3EpUZL9SNd839DcI95lYtMfclPffpFrrJ0BbgryxnrfUSeeSKHu.W9Ur5_DLIBpXO3mfh404_7Kt9o8XZRnLTLyam2fdhB_"
	keyword         = "portainer"
)

func TestPortainer_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword portainer",
			input: fmt.Sprintf("%s token - '%s;'\n%s token - '%s'\n", keyword, validEndpoint, keyword, validToken),
			want:  []string{validToken + validEndpoint},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s;'\n%s token - '%s'\n", keyword, invalidEndpoint, keyword, invalidToken),
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
