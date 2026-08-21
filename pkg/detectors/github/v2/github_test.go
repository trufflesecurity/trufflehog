package github

import (
	"context"
	"strings"
	"testing"

	regexp "github.com/wasilibs/go-re2"

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

// prefixAlternationPat pulls the prefix alternation out of keyPat's source,
// e.g. `(?:ghp|gho|ghu|ghs|ghr|github_pat)_` -> `ghp|gho|ghu|ghs|ghr|github_pat`.
var prefixAlternationPat = regexp.MustCompile(`\(\?:([a-zA-Z0-9_|]+)\)_`)

// keyPatPrefixes derives the token prefixes directly from keyPat's own source
// rather than from a hand-maintained list. If the two disagree, the regex is
// the authority — it is what actually decides whether a token is matched at
// all.
func keyPatPrefixes(t *testing.T) []string {
	t.Helper()

	m := prefixAlternationPat.FindStringSubmatch(keyPat.String())
	if m == nil {
		t.Fatalf("could not find a prefix alternation group in keyPat: %s\n"+
			"keyPat's shape changed; update prefixAlternationPat to match, or this "+
			"drift guard is silently testing nothing.", keyPat.String())
	}

	var prefixes []string
	for _, alt := range strings.Split(m[1], "|") {
		prefixes = append(prefixes, alt+"_")
	}
	return prefixes
}

// TestGithubTokenType_MappingMatchesKeyPatExactly is the drift guard: it
// derives the prefix set from keyPat itself rather than a hand-maintained
// list, so a seventh prefix added to keyPat and forgotten in the map cannot
// slip past silently — the regex and the map cannot diverge without a
// failure.
//
// This matters more than a normal mapping test: an unmapped prefix does not
// crash, it silently reports "Unknown GitHub token", which puts a responder
// back in the position this detector change exists to fix — holding a real
// leaked credential with no idea how to revoke it.
func TestGithubTokenType_MappingMatchesKeyPatExactly(t *testing.T) {
	prefixes := keyPatPrefixes(t)

	if len(prefixes) == 0 {
		t.Fatal("derived zero prefixes from keyPat; the guard is not testing anything")
	}

	fromKeyPat := make(map[string]bool, len(prefixes))
	for _, p := range prefixes {
		fromKeyPat[p] = true
		if _, ok := tokenTypesByPrefix[p]; !ok {
			t.Errorf("keyPat matches prefix %q but tokenTypesByPrefix has no entry for it; "+
				"a leaked token with this prefix would be reported as %q",
				p, "Unknown GitHub token")
		}
	}

	// The reverse direction: a mapping entry for a prefix keyPat cannot match is
	// dead weight, and usually means a prefix was renamed in one place only.
	for p := range tokenTypesByPrefix {
		if !fromKeyPat[p] {
			t.Errorf("tokenTypesByPrefix has an entry for %q, but keyPat never matches that prefix", p)
		}
	}
}

// TestGithubTokenType_EveryKeyPatPrefixResolves closes the loop end to end:
// build a token for each prefix keyPat actually accepts, confirm keyPat
// matches it, and confirm githubTokenType resolves it to something other than
// the unknown fallback. The two tests above check the data structures agree;
// this one checks the behaviour they produce is correct for every real input.
func TestGithubTokenType_EveryKeyPatPrefixResolves(t *testing.T) {
	const unknown = "Unknown GitHub token"

	for _, prefix := range keyPatPrefixes(t) {
		t.Run(prefix, func(t *testing.T) {
			token := prefix + strings.Repeat("a", 36)

			if !keyPat.MatchString(token) {
				t.Fatalf("keyPat does not match %q built from its own prefix alternation; "+
					"the derived prefix is wrong or keyPat's body changed", token)
			}

			got := githubTokenType(token)
			if got == unknown {
				t.Errorf("githubTokenType(%q) = %q; every prefix keyPat matches must resolve to a real type", token, got)
			}
			if got == "" {
				t.Errorf("githubTokenType(%q) returned an empty type", token)
			}
		})
	}
}
