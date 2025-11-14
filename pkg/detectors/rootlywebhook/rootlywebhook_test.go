package rootlywebhook

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestRootlyWebhook_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: "https://webhooks.rootly.com/webhooks/incoming/generic_webhooks?secret=84942ab61f62d34f98511711fd59cedc35bb3a217e6a2399d50a62c01fc4ee9a",
			want:  []string{"84942ab61f62d34f98511711fd59cedc35bb3a217e6a2399d50a62c01fc4ee9a"},
		},
		{
			name:  "valid pattern 2",
			input: "curl -H \"Authorization: Bearer 84942ab61f62d34f98511711fd59cedc35bb3a217e6a2399d50a62c01fc4ee9a\" https://webhooks.rootly.com/webhooks/incoming/generic_webhooks",
			want:  []string{"84942ab61f62d34f98511711fd59cedc35bb3a217e6a2399d50a62c01fc4ee9a"},
		},
		{
			name:  "invalid pattern - short",
			input: "84942ab61f62d34f98511711fd59cedc35bb3a217e6a2399d50a62c01fc4ee9", // 63 chars
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && len(test.want) > 0 {
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
