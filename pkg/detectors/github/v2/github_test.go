package github

import (
	"context"
	"hash/crc32"
	"reflect"
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

// assertNoBlankFields checks that v is not a blank string, or — if v is a
// struct — that none of its exported fields are blank strings. It exists so
// that if a row's value type grows a second field (tokenTypesByPrefix held a
// {TokenType, Remediation} struct before remediation was removed, and could
// again), row validation below catches an unset field automatically instead
// of depending on someone remembering to add a field-specific check.
func assertNoBlankFields(t *testing.T, label string, v reflect.Value) {
	t.Helper()

	switch v.Kind() {
	case reflect.String:
		if strings.TrimSpace(v.String()) == "" {
			t.Errorf("%s: blank value", label)
		}
	case reflect.Struct:
		vt := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := vt.Field(i)
			if !field.IsExported() {
				continue
			}
			assertNoBlankFields(t, label+"."+field.Name, v.Field(i))
		}
	default:
		t.Fatalf("%s: assertNoBlankFields does not know how to validate kind %s; extend the helper for the new row type", label, v.Kind())
	}
}

// TestTokenTypesByPrefix_RowsAreWellFormed checks each row in
// tokenTypesByPrefix in isolation, independent of keyPat. The tests above
// confirm the map's keys line up with keyPat; none of them would catch a
// malformed row added alongside a correct key — e.g. a copy-pasted value
// that leaves two different prefixes describing the same token type, or a
// field left blank.
func TestTokenTypesByPrefix_RowsAreWellFormed(t *testing.T) {
	const unknown = "Unknown GitHub token"

	seenValues := make(map[string]string, len(tokenTypesByPrefix)) // value -> first prefix that used it

	for prefix, tokenType := range tokenTypesByPrefix {
		if prefix == "" {
			t.Error("tokenTypesByPrefix has an empty-string prefix key")
		}
		if !strings.HasSuffix(prefix, "_") {
			t.Errorf("prefix %q does not end in \"_\"; githubTokenType matches by strings.HasPrefix, so a bare prefix can match unrelated tokens", prefix)
		}
		assertNoBlankFields(t, prefix, reflect.ValueOf(tokenType))
		if tokenType == unknown {
			t.Errorf("prefix %q maps to the reserved fallback value %q; a real row must not collide with it", prefix, unknown)
		}
		if other, dup := seenValues[tokenType]; dup {
			t.Errorf("prefixes %q and %q both map to token type %q; each prefix must describe a distinct credential", prefix, other, tokenType)
		} else {
			seenValues[tokenType] = prefix
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

// base62EncodePadded is an independent re-implementation of the checksum
// encoding used only to build test fixtures, so the tests validate the
// production githubChecksum instead of agreeing with it by construction.
func base62EncodePadded(value uint64, width int) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var digits []byte
	if value == 0 {
		digits = []byte{'0'}
	} else {
		for value > 0 {
			digits = append(digits, alphabet[value%62])
			value /= 62
		}
		for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
			digits[i], digits[j] = digits[j], digits[i]
		}
	}
	if len(digits) >= width {
		return string(digits)
	}
	return strings.Repeat("0", width-len(digits)) + string(digits)
}

// makeClassicToken builds a classic-format token: prefix + 30-char body +
// 6-char base62 CRC32 checksum of the body.
func makeClassicToken(prefix, body string) string {
	return prefix + body + base62EncodePadded(uint64(crc32.ChecksumIEEE([]byte(body))), 6)
}

func TestGithub_HasValidClassicChecksum(t *testing.T) {
	body := "ringAbC123dEf456GhI789jKlMnOpQ"
	if len(body) != 30 {
		t.Fatalf("fixture body len %d, want 30", len(body))
	}
	valid := makeClassicToken("ghp_", body)

	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{name: "valid classic token", token: valid, want: true},
		{name: "corrupted checksum", token: valid[:39] + "A", want: false},
		{name: "too short", token: valid[:39], want: false},
		{name: "too long", token: valid + "A", want: false},
		{name: "fine-grained PAT has no classic checksum", token: "github_pat_" + strings.Repeat("A", 82), want: false},
		{name: "not a token", token: "not_a_github_token", want: false},
	}
	// The corrupted-checksum case is only meaningful if the flip actually
	// changed the token.
	if tests[1].token == valid {
		tests[1].token = valid[:39] + "B"
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := hasValidClassicChecksum(test.token); got != test.want {
				t.Errorf("hasValidClassicChecksum(%q) = %v, want %v", test.token, got, test.want)
			}
		})
	}
}

// TestGithub_IsFalsePositive_ChecksumValidClassicTokenSkipsWordList is the
// regression test for #5572: a classic token whose 30-char body happens to
// contain a listed word (ring, hmac, open, and the other words from the
// report) was dropped by the default word-list check before verification
// ever ran, about 1 in 300 tokens. A checksum-valid token must survive the
// false-positive check; only a token whose checksum fails still goes
// through the word lists.
func TestGithub_IsFalsePositive_ChecksumValidClassicTokenSkipsWordList(t *testing.T) {
	// 30-char bodies, each containing one word from the report.
	bodies := map[string]string{
		"ring": "ringAbC123dEf456GhI789jKlMnOpQ",
		"hmac": "hmacAbC123dEf456GhI789jKlMnOpQ",
		"open": "openAbC123dEf456GhI789jKlMnOpQ",
		"role": "roleAbC123dEf456GhI789jKlMnOpQ",
		"byte": "byteAbC123dEf456GhI789jKlMnOpQ",
		"rest": "restAbC123dEf456GhI789jKlMnOpQ",
		"part": "partAbC123dEf456GhI789jKlMnOpQ",
		"calc": "calcAbC123dEf456GhI789jKlMnOpQ",
		"head": "headAbC123dEf456GhI789jKlMnOpQ",
	}

	check := detectors.GetFalsePositiveCheck(Scanner{})

	for word, body := range bodies {
		t.Run(word, func(t *testing.T) {
			if len(body) != 30 {
				t.Fatalf("fixture body len %d, want 30", len(body))
			}
			token := makeClassicToken("ghp_", body)

			// Pin the bug mechanism: the default check drops this token.
			if fp, reason := detectors.IsKnownFalsePositive(token, detectors.DefaultFalsePositives, true); !fp {
				t.Fatalf("default check kept %q; the fixture no longer reproduces the word-list drop (%q)", token, reason)
			}

			// The fix: the engine check must keep the checksum-valid token.
			if fp, reason := check(detectors.Result{Raw: []byte(token)}); fp {
				t.Errorf("checksum-valid token containing %q dropped as false positive: %s", word, reason)
			}

			// A token with a broken checksum gets no exemption.
			corrupt := token[:39] + "A"
			if corrupt == token {
				corrupt = token[:39] + "B"
			}
			if fp, _ := check(detectors.Result{Raw: []byte(corrupt)}); !fp {
				t.Errorf("checksum-invalid token containing %q was kept; it must still go through the word lists", word)
			}
		})
	}
}

// TestGithub_IsFalsePositive_ChecksumValidTokenEveryClassicPrefix checks the
// exemption applies to every classic prefix, not just ghp_.
func TestGithub_IsFalsePositive_ChecksumValidTokenEveryClassicPrefix(t *testing.T) {
	body := "ringAbC123dEf456GhI789jKlMnOpQ"
	check := detectors.GetFalsePositiveCheck(Scanner{})

	for _, prefix := range classicTokenPrefixes {
		t.Run(prefix, func(t *testing.T) {
			token := makeClassicToken(prefix, body)
			if fp, reason := check(detectors.Result{Raw: []byte(token)}); fp {
				t.Errorf("checksum-valid %q token dropped as false positive: %s", prefix, reason)
			}
		})
	}
}

// TestGithub_IsFalsePositive_ValidTokenWithoutWordStillReported is the sanity
// control: a checksum-valid token with no listed word in its body was never
// dropped, and still is not.
func TestGithub_IsFalsePositive_ValidTokenWithoutWordStillReported(t *testing.T) {
	body := "AbC123dEf456GhI789jKlMnOpQrStU"
	if len(body) != 30 {
		t.Fatalf("fixture body len %d, want 30", len(body))
	}
	token := makeClassicToken("ghp_", body)
	check := detectors.GetFalsePositiveCheck(Scanner{})
	if fp, reason := check(detectors.Result{Raw: []byte(token)}); fp {
		t.Errorf("checksum-valid token without a listed word dropped as false positive: %s", reason)
	}
}
