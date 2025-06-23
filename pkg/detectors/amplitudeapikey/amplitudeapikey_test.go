package amplitudeapikey

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `
	amplitude key = 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
	amplitude secret = 5b3c4d5e5f7a8b9c0d1e2f2f3a4b4c6e
	`
	invalidPattern = `
	amplitude key = 1a2b3c4d5e6f7a8g9c0d1e2f3a4b5c6d
	amplitude secret = 5b3c4d5e5f7a8b9c0d1r2f2f3a4b4c6e
	`
)

func TestAmplitudeAPIKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("amplitude: '%s'", validPattern),
			want: []string{
				"1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d5b3c4d5e5f7a8b9c0d1e2f2f3a4b4c6e",
				"5b3c4d5e5f7a8b9c0d1e2f2f3a4b4c6e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
			},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("amplitude: '%s'", invalidPattern),
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
