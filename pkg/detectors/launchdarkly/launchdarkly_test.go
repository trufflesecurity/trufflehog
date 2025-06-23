package launchdarkly

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestLaunchDarkly_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - launchdarkly api key",
			input: `api-5gykyl1b-wgrq-41lc-z6q1-h7zn5fdlcybw`,
			want:  []string{"api-5gykyl1b-wgrq-41lc-z6q1-h7zn5fdlcybw"},
		},
		{
			name:  "valid pattern - launchdarkly sdk key",
			input: `sdk-5gykyl1b-wgrq-41lc-z6q1-h7zn5fdlcybw`,
			want:  []string{"sdk-5gykyl1b-wgrq-41lc-z6q1-h7zn5fdlcybw"},
		},
		{
			name:  "invalid pattern - invalid length",
			input: `sdk-5gykyl1b-wgrq-41lc-z6q1-h7zn5fdlcyb`,
			want:  []string{},
		},
		{
			name:  "invalid pattern - invalid character",
			input: `api-5Gykyl1b-Wgrq-41lC-z6q1-h7zn5fdlcybw`,
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
