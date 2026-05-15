package cloudflareapitoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestCloudFlareAPITokenV2_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid v2 user token - no keyword proximity needed",
			input: "token: cfut_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfe",
			want:  []string{"cfut_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfe"},
		},
		{
			name:  "valid v2 account token - no keyword proximity needed",
			input: "token: cfat_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfe",
			want:  []string{"cfat_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfe"},
		},
		{
			name:  "no match for legacy format",
			input: "cfut_: kOjD1yceduu2jxL2uuwT9dkOIudU3_54sLCEud6j",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && test.want != nil {
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
