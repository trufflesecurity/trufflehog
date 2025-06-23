package twitchaccesstoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestTwitchaccesstoken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: "twitchaccesstoken_token = 'abc123def456ghi789jkl012mno345'",
			want:  []string{"abc123def456ghi789jkl012mno345"},
		},
		{
			name:  "env variable pattern",
			input: "'twitch_access_token': 'abc123def456ghi789jkl012mno345'",
			want:  []string{"abc123def456ghi789jkl012mno345"},
		},
		{
			name:  "get request pattern - keyword out of range",
			input: "curl -X GET 'https://id.twitch.tv/oauth2/validate' -H 'Authorization: OAuth xbc123def456ghi789jkl012mno345'",
			want:  []string{},
		},
		{
			name:  "finds all matches",
			input: "twitchaccesstoken_token1 = 'z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5' twitchaccesstoken_token2 = '123abc456def789ghi012jkl345mno'",
			want:  []string{"z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5", "123abc456def789ghi012jkl345mno"},
		},
		{
			name:  "invald pattern",
			input: "twitchaccesstoken_token = '1a2b3c4d'",
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
