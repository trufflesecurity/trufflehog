package openai

import (
	"context"
	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"testing"
)

func TestOpenAI_DoesNotMatchAdminKeys(t *testing.T) {
	d := Scanner{}
	adminKey := `OPENAI_ADMIN_KEY = "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"`

	results, err := d.FromData(context.Background(), false, []byte(adminKey))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("openai detector should not match admin keys, but got %d results", len(results))
	}
}

func TestOpenAI_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "user API key",
			input: "openai.api-key: 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",
			want:  []string{"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"},
		},
		{
			name:  "project API key",
			input: `OPENAI_API_KEY = "sk-proj-mpjtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiagE8K"`,
			want:  []string{"sk-proj-mpjtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiagE8K"},
		},
		{
			name:  "service account API key",
			input: `OPENAI_API_KEY = "sk-service-account-name-Ofbtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiaglyC"`,
			want:  []string{"sk-service-account-name-Ofbtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiaglyC"},
		},
		{
			name:  "newer user API key",
			input: `"OPENAI_API_KEY = "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"`,
			want:  []string{"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"},
		},
		{
			name:  "newer service account API key",
			input: `OPENAI_API_KEY = "sk-svcacct-IUXtc5gIZK-2cBfB-nTgEWbD8mi-fi-gc20oGtq8ve51sET3BlbkFJCg8iQkCVz_nmE_q1dCWlMpemoaoMqHzQ6D-FnWGqlz4C8A"`,
			want:  []string{"sk-svcacct-IUXtc5gIZK-2cBfB-nTgEWbD8mi-fi-gc20oGtq8ve51sET3BlbkFJCg8iQkCVz_nmE_q1dCWlMpemoaoMqHzQ6D-FnWGqlz4C8A"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(detectorMatches) == 0 {
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
