package wrike

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "eyHrUMIkHqmEhqDBTWcuk5kL.tRiP-uQD9ZZSHfYYzdqRYHgkfiPEplgL1INSyA_c9VgbpVIzvFhVx0vzWzhxv9CdyLTr6FCvmDDrxM5BU0gQdyDGgXosinkyl4Z_7OIbHY08sImeavc-fxQ1OzVo6mqb-bDmxwuVWIE5WXb2bcRRnKotFAa4.pCkZAYDxZd66Yt6fK7HM33G6Rr.ALuDQg2mFdemMy1_WIOh9-0l6b6iP2anAp0CbxpcXlrecGHaMgrgzla41NrfpzWjAKlOwq.hbIKdPLLK0bOvg2m6ETkKdGhfRRHkYAqyYO.EhONITs48Eb21kDH0gc"
	invalidPattern = "ey?rUMIkHqmEhqDBTWcuk5kL.tRiP-uQD9ZZSHfYYzdqRYHgkfiPEplgL1INSyA_c9VgbpVIzvFhVx0vzWzhxv9CdyLTr6FCvmDDrxM5BU0gQdyDGgXosinkyl4Z_7OIbHY08sImeavc-fxQ1OzVo6mqb-bDmxwuVWIE5WXb2bcRRnKotFAa4.pCkZAYDxZd66Yt6fK7HM33G6Rr.ALuDQg2mFdemMy1_WIOh9-0l6b6iP2anAp0CbxpcXlrecGHaMgrgzla41NrfpzWjAKlOwq.hbIKdPLLK0bOvg2m6ETkKdGhfRRHkYAqyYO.EhONITs48Eb21kDH0gc"
	keyword        = "wrike"
)

func TestWrike_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword wrike",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("%s token = '%s' | '%s'", keyword, validPattern, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s'", keyword, validPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s = '%s'", keyword, invalidPattern),
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
