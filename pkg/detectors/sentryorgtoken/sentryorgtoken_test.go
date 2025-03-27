package sentryorgtoken

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `
	sentry_token := sntrys_eyJFAKEiOjE3NDIzNjM1NTIuNTAzMzA5LCJ1cmwiOiJodHRwczovL3NlbnRyeS5pbyIsInJlZ2lvbl91cmwiOiJodHRwczovL3VzLnNlbnRyeS5pbfakem9yZyI6InRydWZmbGUtc2VjdXJpdHktamQifQ==_+zqSnKjs87cicc3FAK08vmZs5cWx9C5EARKHFtW5lqI
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sentry_token))
	`
	invalidPattern = "sntrys_eyJFAKE-OjE3NDIzNjM1NTIuNTAzMzA5LCJ1cmwiOiJodHRwczovL3NlbnRyeS5pbyIsInJlZ2lvbl91cmwiOiJodHRwczovL3VzLnNlbnRyeS5pbfakem9yZyI6InRydWZmbGUtc2VjdXJpdHktamQifQ==_+zqSnKjs87cicc3FAK08vmZs5cWx9C5EARKHFtW5lqI"
	token          = "sntrys_eyJFAKEiOjE3NDIzNjM1NTIuNTAzMzA5LCJ1cmwiOiJodHRwczovL3NlbnRyeS5pbyIsInJlZ2lvbl91cmwiOiJodHRwczovL3VzLnNlbnRyeS5pbfakem9yZyI6InRydWZmbGUtc2VjdXJpdHktamQifQ==_+zqSnKjs87cicc3FAK08vmZs5cWx9C5EARKHFtW5lqI"
)

func TestSentryToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword sentry org token",
			input: validPattern,
			want:  []string{token},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("token = '%s' | '%s'", validPattern, validPattern),
			want:  []string{token},
		},
		{
			name:  "invalid pattern",
			input: invalidPattern,
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
