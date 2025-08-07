package phraseaccesstoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestPhrase_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - with keyword phrase",
			input: `
			[INFO] Initializing authentication
			[DEBUG] phrase token = 1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890
			[Info] Response received: 200 OK
			`,
			want: []string{"1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890"},
		},
		{
			name: "valid pattern - ignore duplicate",
			input: `
			[INFO] Processing authentication tokens
			[DEBUG] phrase token = '1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'
			[WARN] Duplicate token found: phrase token = '1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'
			[Info] Response received: 200 OK
			`,
			want: []string{"1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890"},
		},
		{
			name: "valid pattern - key out of prefix range",
			input: `
			[INFO] Starting system initialization
			[DEBUG] phrase keyword is not close to the real key in the data
			[DEBUG] Configuration loaded successfully
			[DEBUG] Secret key = '1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'
			[ERROR] Response received: 400 BadRequest
			`,
			want: nil,
		},
		{
			name: "invalid pattern",
			input: `
			[INFO] Loading configuration
			[DEBUG] phrase = 7cf4135a4e7f7ac228d36f210f151917a86f5dbd6
			[ERROR] Response received: 400 BadRequest
			`,
			want: nil,
		},
		{
			name: "finds all valid matches",
			input: `
			[INFO] Multi-token authentication
			[DEBUG] phrase token1 = '1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'
			[DEBUG] phrase token2 = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
			[Info] Response received: 200 OK
			`,
			want: []string{"1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
		},
		{
			name: "invalid pattern - too short",
			input: `
			[INFO] Processing short token
			[DEBUG] phrase = '1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678'
			[ERROR] Response received: 400 BadRequest
			`,
			want: nil,
		},
		{
			name: "invalid pattern - too long",
			input: `
			[INFO] Processing long token
			[DEBUG] phrase = '1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef123456789012'
			[ERROR] Response received: 400 BadRequest
			`,
			want: nil,
		},
		{
			name: "invalid pattern - contains uppercase",
			input: `
			[INFO] Processing token with uppercase
			[DEBUG] phrase = '1A2B3C4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'
			[ERROR] Response received: 400 BadRequest
			`,
			want: nil,
		},
		{
			name: "invalid pattern - contains special characters",
			input: `
			[INFO] Processing token with special chars
			[DEBUG] phrase = '1a2b3c4d-e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'
			[ERROR] Response received: 400 BadRequest
			`,
			want: nil,
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
