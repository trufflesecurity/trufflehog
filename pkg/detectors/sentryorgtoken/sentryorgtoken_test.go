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

	// org slug "acme-co"
	shortSlugToken = "sntrys_eyJFAKEiOjE3NDIzNjM1NTIuNTAzMzA5LCJ1cmwiOiJodHRwczovL3NlbnRyeS5pbyIsInJlZ2lvbl91cmwiOiJodHRwczovL3VzLnNlbnRyeS5pbyIsIm9yZyI6ImFjbWUtY28ifQ==_+zqSnKjs87cicc3FAK08vmZs5cWx9C5EARKHFtW5lqI"
	// self-hosted url "https://sentry.internal.example-company.com"
	selfHostedToken = "sntrys_eyJFAKEiOjE3NDIzNjM1NTIuNTAzMzA5LCJ1cmwiOiJodHRwczovL3NlbnRyeS5pbnRlcm5hbC5leGFtcGxlLWNvbXBhbnkuY29tIiwicmVnaW9uX3VybCI6Imh0dHBzOi8vc2VudHJ5LmludGVybmFsLmV4YW1wbGUtY29tcGFueS5jb20iLCJvcmciOiJwbGF0Zm9ybS1lbmdpbmVlcmluZyJ9_+zqSnKjs87cicc3FAK08vmZs5cWx9C5EARKHFtW5lqI"
	// self-hosted with 100-char urls and a long org slug
	longSelfHostedToken = "sntrys_eyJFAKEiOjE3NDIzNjM1NTIuNTAzMzA5LCJ1cmwiOiJodHRwczovL3h4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4LmV4YW1wbGUuY29tIiwicmVnaW9uX3VybCI6Imh0dHBzOi8veHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHguZXhhbXBsZS5jb20iLCJvcmciOiJwbGF0Zm9ybS1lbmdpbmVlcmluZy1vYnNlcnZhYmlsaXR5LXRlYW0tdXMtZWFzdCJ9_+zqSnKjs87cicc3FAK08vmZs5cWx9C5EARKHFtW5lqI"
	shortSecretPattern  = "sntrys_eyJFAKEiOjE3NDIzNjM1NTIuNTAzMzA5LCJ1cmwiOiJodHRwczovL3NlbnRyeS5pbyIsInJlZ2lvbl91cmwiOiJodHRwczovL3VzLnNlbnRyeS5pbyIsIm9yZyI6ImFjbWUtY28ifQ==_+zqSnKjs87cicc3FAK08vmZs5cWx9C5EARKHFtW5lq"
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
			name:  "valid pattern - short org slug",
			input: fmt.Sprintf("SENTRY_AUTH_TOKEN=%s\n", shortSlugToken),
			want:  []string{shortSlugToken},
		},
		{
			name:  "valid pattern - self-hosted url",
			input: fmt.Sprintf("authToken: '%s'", selfHostedToken),
			want:  []string{selfHostedToken},
		},
		{
			name:  "valid pattern - long self-hosted url",
			input: fmt.Sprintf("SENTRY_AUTH_TOKEN=%s\n", longSelfHostedToken),
			want:  []string{longSelfHostedToken},
		},
		{
			name:  "invalid pattern",
			input: invalidPattern,
			want:  []string{},
		},
		{
			name:  "invalid pattern - secret too short",
			input: fmt.Sprintf("SENTRY_AUTH_TOKEN=%s\n", shortSecretPattern),
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
