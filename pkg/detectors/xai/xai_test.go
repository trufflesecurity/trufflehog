package xai

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestVerifyMatch_KeyState(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantVerified bool
	}{
		{
			name:         "active key",
			body:         `{"api_key_blocked":false,"api_key_disabled":false}`,
			wantVerified: true,
		},
		{
			name:         "blocked key",
			body:         `{"api_key_blocked":true,"api_key_disabled":false}`,
			wantVerified: false,
		},
		{
			name:         "disabled key",
			body:         `{"api_key_blocked":false,"api_key_disabled":true}`,
			wantVerified: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verified, _, err := verifyMatch(context.Background(), common.ConstantResponseHttpClient(200, tt.body), "xai-test")
			if err != nil {
				t.Fatal(err)
			}
			if verified != tt.wantVerified {
				t.Errorf("verified = %v, want %v", verified, tt.wantVerified)
			}
		})
	}
}

func TestXai_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: "xai_token = 'xai-W5zbfUkzlXedo7qD42AbBLlRSsyJrOW5zbfUkzlXedo7qD42AbBLlRSsyJrOW5zbfUkzlXedo7qD42Ab'",
			want:  []string{"xai-W5zbfUkzlXedo7qD42AbBLlRSsyJrOW5zbfUkzlXedo7qD42AbBLlRSsyJrOW5zbfUkzlXedo7qD42Ab"},
		},
		{
			name: "finds all matches",
			input: `grok_token1 = 'xai-W5zbfUkzlXedo7qD42AbBLlRSsyJrOW5zbfUkzlXedo7qD42AbBLlRSsyJrOW5zbfUkzlXedo7qD42Ab'
xai_token2 = 'xai-W5zbfUkzlXedo7qD42AbBLlRSsyJr1W5zbfUkzlXedo7qD42AbBLlRSsyJrOW5zbfUkzlXedo7qD42Ab'`,
			want: []string{"xai-W5zbfUkzlXedo7qD42AbBLlRSsyJrOW5zbfUkzlXedo7qD42AbBLlRSsyJrOW5zbfUkzlXedo7qD42Ab", "xai-W5zbfUkzlXedo7qD42AbBLlRSsyJr1W5zbfUkzlXedo7qD42AbBLlRSsyJrOW5zbfUkzlXedo7qD42Ab"},
		},
		{
			name:  "invalid pattern",
			input: "xai_token = 'xai-W5zbfUkzlXedo7qD42AbBLlRSsyJrOW5zbfUkzlXe'",
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
