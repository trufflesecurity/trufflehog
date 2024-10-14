package agora

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validKeyPattern    = "asdf0987mnbv1234qsxojb6ygb2wsx0o"
	validSecretPattern = "beqr7215fr4g6bfjkmnvxrtygb2wsxap"
	complexPattern     = `agora credentials
							these are some example credentails for login.
							use these to login.
							key: asdf0987mnbv1234qsxojb6ygb2wsx0o
							secret: beqr7215fr4g6bfjkmnvxrtygb2wsxap
							loginUrl: https://www.agora.com/example_login
						`
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
			input: fmt.Sprintf("agora key='%s' - secret='%s'", validKeyPattern, validSecretPattern),
			want:  []string{validKeyPattern + validSecretPattern},
		},
		{
			name:  "valid complex pattern",
			input: fmt.Sprintf("agora data='%s'", complexPattern),
			want:  []string{validKeyPattern + validSecretPattern},
		},
		{
			name:  "valid pattern - out of prefix range",
			input: fmt.Sprintf("agora keyword is not close to the real key or secret = '%s|%s'", validKeyPattern, validSecretPattern),
			want:  nil,
		},
		{
			name:  "valid pattern - only key",
			input: fmt.Sprintf("agora key%s", validKeyPattern),
			want:  nil,
		},
		{
			name:  "valid pattern - only secret",
			input: fmt.Sprintf("agora secret%s", validSecretPattern),
			want:  nil,
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
