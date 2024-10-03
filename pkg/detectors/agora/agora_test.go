package agora

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "asdf0987mnbv1234qsxojb6ygb2wsx0o/beqr7215fr4g6bfjkmnvxrtygb2wsxap"
	invalidPattern = "asdf0987mNbv1234qsxojb6ygb2w$x0o/beqr7215fr4g6bfjkmnVxrtygb2wsxap"
)

func TestAgora_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("agora = '%s'", validPattern),
			want:  []string{"asdf0987mnbv1234qsxojb6ygb2wsx0oasdf0987mnbv1234qsxojb6ygb2wsx0o"},
		},
		{
			name:  "valid pattern - out of prefix range",
			input: fmt.Sprintf("agora keyword is not close to the real key and secret = '%s'", validPattern),
			want:  nil,
		},
		{
			name:  "valid pattern - only key",
			input: fmt.Sprintf("agora %s", strings.Split(validPattern, "/")[0]),
			want:  []string{"asdf0987mnbv1234qsxojb6ygb2wsx0oasdf0987mnbv1234qsxojb6ygb2wsx0o"},
		},
		{
			name:  "valid pattern - only secret",
			input: fmt.Sprintf("agora %s", strings.Split(validPattern, "/")[1]),
			want:  []string{"beqr7215fr4g6bfjkmnvxrtygb2wsxapbeqr7215fr4g6bfjkmnvxrtygb2wsxap"},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("agora %s", invalidPattern),
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
