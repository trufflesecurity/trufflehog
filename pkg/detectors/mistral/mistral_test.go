package mistral

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestMistral_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: "mistral_api_key = 'aB12cD34eF56gH78iJ90kL12mN34oP56'",
			want:  []string{"aB12cD34eF56gH78iJ90kL12mN34oP56"},
		},
		{
			name:  "env var style",
			input: "MISTRAL_API_KEY=Zx9YwV8uT7sR6qP5oN4mL3kJ2iH1gF0e",
			want:  []string{"Zx9YwV8uT7sR6qP5oN4mL3kJ2iH1gF0e"},
		},
		{
			name:  "no keyword nearby",
			input: "some_other_key = 'aB12cD34eF56gH78iJ90kL12mN34oP56'",
			want:  nil,
		},
		{
			name:  "wrong length (31 chars)",
			input: "mistral_api_key = 'aB12cD34eF56gH78iJ90kL12mN34oP5'",
			want:  nil,
		},
		{
			name:  "wrong length (33 chars)",
			input: "mistral_api_key = 'aB12cD34eF56gH78iJ90kL12mN34oP567'",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(detectorMatches) == 0 && len(test.want) > 0 {
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
