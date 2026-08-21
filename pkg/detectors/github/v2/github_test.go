package github

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `[{
		"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
		"name": "Github",
		"type": "Detector",
		"api": true,
		"authentication_type": "",
		"verification_url": "https://api.example.com/example",
		"test_secrets": {
			"github_secret": "ghs_RWGUZ6kS8_Ut7PbtR72k2miJwwYtxkpe8mOpT8feAWYZcwz43PxBVGCNATnycaQV9VUlPJe1uST5Xen7d3uZ5lilVlEVvT9AbxnhURdT3OzPtCvXydIrvE4LrDO"
		},
		"expected_response": "200",
		"method": "GET",
		"deprecated": false
	}]`
	secret = "ghs_RWGUZ6kS8_Ut7PbtR72k2miJwwYtxkpe8mOpT8feAWYZcwz43PxBVGCNATnycaQV9VUlPJe1uST5Xen7d3uZ5lilVlEVvT9AbxnhURdT3OzPtCvXydIrvE4LrDO"
)

func TestGithub_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: validPattern,
			want:  []string{secret},
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

func TestGithubTokenType(t *testing.T) {
	tests := []struct {
		prefix string
		token  string
		want   string
	}{
		{"ghp_", "ghp_" + strings.Repeat("a", 36), "Personal Access Token (classic)"},
		{"github_pat_", "github_pat_" + strings.Repeat("a", 36), "Personal Access Token (fine-grained)"},
		{"gho_", "gho_" + strings.Repeat("a", 36), "OAuth Access Token"},
		{"ghu_", "ghu_" + strings.Repeat("a", 36), "GitHub App User-to-Server Token"},
		{"ghs_", "ghs_" + strings.Repeat("a", 36), "GitHub App Server-to-Server (installation) Token"},
		{"ghr_", "ghr_" + strings.Repeat("a", 36), "GitHub App Refresh Token"},
		{"unknown", "not_a_github_token", "Unknown GitHub token"},
	}

	for _, test := range tests {
		t.Run(test.prefix, func(t *testing.T) {
			got := githubTokenType(test.token)
			if got != test.want {
				t.Errorf("githubTokenType(%q) = %q, want %q", test.token, got, test.want)
			}
		})
	}
}

// TestGithubTokenType_KeyPatPrefixesCovered guards against drift: every
// prefix matched by keyPat must have an entry in tokenTypesByPrefix, so a new
// token format added to the regex doesn't silently fall back to "Unknown
// GitHub token".
func TestGithubTokenType_KeyPatPrefixesCovered(t *testing.T) {
	keyPatPrefixes := []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}

	for _, prefix := range keyPatPrefixes {
		if _, ok := tokenTypesByPrefix[prefix]; !ok {
			t.Errorf("keyPat prefix %q has no entry in tokenTypesByPrefix", prefix)
		}
	}

	if len(tokenTypesByPrefix) != len(keyPatPrefixes) {
		t.Errorf("tokenTypesByPrefix has %d entries, expected %d to match keyPat prefixes exactly", len(tokenTypesByPrefix), len(keyPatPrefixes))
	}
}
