package railwayapp

import (
	"context"
	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"testing"
)

func TestRailwayApp_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern - with keyword railwayapp",
			input: "railwayapp token = 'a52a85d1-33c4-4808-8fa0-c375f3c6013a'",
			want:  []string{"a52a85d1-33c4-4808-8fa0-c375f3c6013a"},
		},
		{
			name:  "typical pattern - with keyword railway",
			input: "railway = 'a52a85d1-33c4-4808-8fa0-c375f3c6013a'",
			want:  []string{"a52a85d1-33c4-4808-8fa0-c375f3c6013a"},
		},
		{
			name:  "typical pattern - ignore duplicate",
			input: "railwayapp token = 'a52a85d1-33c4-4808-8fa0-c375f3c6013a | a52a85d1-33c4-4808-8fa0-c375f3c6013a'",
			want:  []string{"a52a85d1-33c4-4808-8fa0-c375f3c6013a"},
		},
		{
			name:  "invalid pattern",
			input: "railway = 'a52e95g1-33c4-4808-8fa0-b375f3c6013a'",
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
