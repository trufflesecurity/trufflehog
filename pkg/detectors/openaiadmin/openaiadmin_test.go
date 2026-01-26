package openaiadmin

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestOpenAIAdmin_DoesNotMatchRegularKeys(t *testing.T) {
	d := Scanner{}

	regularKeys := []struct {
		name  string
		input string
	}{
		{
			name:  "legacy key",
			input: `OPENAI_API_KEY = "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"`,
		},
		{
			name:  "project key",
			input: `OPENAI_API_KEY = "sk-proj-mpjtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiagE8K"`,
		},
		{
			name:  "service account key",
			input: `OPENAI_API_KEY = "sk-svcacct-IUXtc5gIZK-2cBfB-nTgEWbD8mi-fi-gc20oGtq8ve51sET3BlbkFJCg8iQkCVz_nmE_q1dCWlMpemoaoMqHzQ6D-FnWGqlz4C8A"`,
		},
		{
			name:  "service account key (old format)",
			input: `OPENAI_API_KEY = "sk-service-account-name-Ofbtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiaglyC"`,
		},
	}

	for _, tc := range regularKeys {
		t.Run(tc.name, func(t *testing.T) {
			results, err := d.FromData(context.Background(), false, []byte(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(results) != 0 {
				t.Errorf("openaiadmin detector should not match %s, but got %d results", tc.name, len(results))
			}
		})
	}
}

func TestOpenAIAdmin_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid admin key - example 1",
			input: `
				[INFO] Authenticating with OpenAI Admin API
				[DEBUG] Admin Key=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
				[INFO] Successfully authenticated
			`,
			want: []string{"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"},
		},
		{
			name: "valid admin key - example 2",
			input: `
				export OPENAI_ADMIN_KEY="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"
			`,
			want: []string{"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"},
		},
		{
			name: "valid admin key - example 3",
			input: `
				{
					"openai_admin_api_key": "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"
				}
			`,
			want: []string{"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"},
		},
		{
			name: "multiple admin keys",
			input: `
				# Development environment
				OPENAI_ADMIN_KEY_DEV=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
				# Production environment
				OPENAI_ADMIN_KEY_PROD=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
			`,
			want: []string{
				"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",
				"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",
			},
		},
		{
			name: "regular OpenAI key should not match",
			input: `
				# This is a regular OpenAI key, not an admin key
				OPENAI_API_KEY=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
			`,
			want: []string{},
		},
		{
			name: "project key should not match",
			input: `
				OPENAI_API_KEY = "sk-proj-mpjtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiagE8K"
			`,
			want: []string{},
		},
		{
			name: "invalid - missing T3BlbkFJ signature",
			input: `
				# This looks like an admin key but is missing the OpenAI signature
				FAKE_KEY=sk-admin-JWARXiHjpLXSh6W_0pFGb3sW7yr0cKheXXtWGMY0Q8kbBNqsxLskJy0LCOABCDEFGHgTJWgjMvdi6YlPvdXRqmSlZ4dLK-nFxUG2d9Tgaz5Q6weGVNBaLuUmMV4A
			`,
			want: []string{},
		},
		{
			name: "invalid - wrong length (too short before signature)",
			input: `
				# Admin key with incorrect length
				BAD_KEY=sk-admin-shortT3BlbkFJgTJWgjMvdi6YlPvdXRqmSlZ4dLK-nFxUG2d9Tgaz5Q6weGVNBaLuUmMV4A
			`,
			want: []string{},
		},
		{
			name: "invalid - wrong length (too short after signature)",
			input: `
				# Admin key with incorrect length
				BAD_KEY=sk-admin-JWARXiHjpLXSh6W_0pFGb3sW7yr0cKheXXtWGMY0Q8kbBNqsxLskJy0LCOT3BlbkFJshort
			`,
			want: []string{},
		},
		{
			name: "no matches",
			input: `
				Some random text without any keys
			`,
			want: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Skip keyword check for tests that don't expect matches
			if len(test.want) > 0 {
				matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
				if len(matchedDetectors) == 0 {
					t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
					return
				}
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
