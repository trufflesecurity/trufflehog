package discordbottoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

const (
	// Modern token shape: 26.6.38 (longer ID and HMAC segments than legacy tokens).
	// The token appears on its own, with no separate numeric ID alongside it.
	modernToken = "MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.G00g7H.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB"
	// Legacy token shape: 24.6.27.
	legacyToken = "oHILWmk3qakMYbqAikD9R0nJ.Vhu0LY.FK1U_2L2Of8Bm5ESbD6Cy4VKu2K"
)

func TestDiscordBotToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "modern token, no separate id",
			input: `discord_bot_token = "` + modernToken + `"`,
			want:  []string{modernToken},
		},
		{
			name:  "legacy token",
			input: `discord_bot_token = "` + legacyToken + `"`,
			want:  []string{legacyToken},
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
