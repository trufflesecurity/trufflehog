package ldap

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
	validUriPattern        = "ldaps://127.0.0.1:389"
	invalidUriPattern      = "idaps://127.0.0.1:389"
	validUsernamePattern   = "cCOfHuyrVdDdcWCAbKLCSAlospWAdCmfKwr="
	invalidUsernamePattern = "0fHuy2VdDdcWCAbKLC412lospWAdCmfKwr9="
	validPasswordPattern   = "A:J$NL9~6:u:L$_:VO4tf))h#v0i}O"
	invalidPasswordPattern = "A:J$NL9~6:u:L$_:VO4tf))h#v0i}O"
	validIadPattern        = "OpenDSObject(\"ldaps://www\", \"ABC\", \"XYZ\", 123)"
	invalidIadPattern      = "OpenDSObject(\"ldaps://www\", \"ABC\", \"XYZ\", ?)"
)

func TestLdap_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("%s bind '%s' pass '%s' %s", validUriPattern, validIadPattern, validPasswordPattern, validUsernamePattern),
			want:  []string{"ldaps://www\tABC\tXYZ"},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s key = bind '%s' pass '%s %s", invalidUriPattern, invalidUsernamePattern, invalidPasswordPattern, invalidIadPattern),
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

// TestCartesianProductExplosion constructs N distinct URIs, usernames and
// passwords.  A naïve triple-nested loop inside the detector would produce
// N³ candidate combinations and quickly blow up.
//  1. scores combinations by textual proximity,
//  2. keeps only the best few (maxCombinations), and
//  3. applies an overall safety-cap (maxResults),
//
// so we should never see the full Cartesian product.  The test also injects a
// single high-confidence IAD line to guarantee at least one positive result.
func TestCartesianProductExplosion(t *testing.T) {
	const N = 20 // number of URIs, usernames and passwords we generate

	var b strings.Builder

	// 1.  N distinct LDAP URIs.
	for i := range N {
		b.WriteString(fmt.Sprintf("ldap://host%d:389\n", i))
	}

	// 2.  N distinct bind-DNs (letters only to satisfy usernamePat).
	for i := range N {
		letter := 'A' + rune(i%26)
		b.WriteString(fmt.Sprintf(`bind="cn=user%c,dc=example,dc=org"`+"\n", letter))
	}

	// 3.  N distinct passwords.
	for i := range N {
		b.WriteString(fmt.Sprintf(`pass="P@ssw0rd%02d"`+"\n", i))
	}

	// 4.  Add one high-confidence IAD line to guarantee at least one hit.
	b.WriteString(
		`Set ou = dso.OpenDSObject("LDAP://host999:389", ` +
			`"cn=admin,dc=example,dc=org", "SuperSecret", 1)` + "\n")

	payload := []byte(b.String())

	results, err := (Scanner{}).FromData(context.Background(), false, payload)
	if err != nil {
		t.Fatalf("FromData error: %v", err)
	}

	if got := len(results); got == 0 {
		t.Fatalf("expected at least 1 result, got 0")
	} else if got > maxResults {
		t.Fatalf("expected at most %d results (safety cap), got %d", maxResults, got)
	} else {
		t.Logf("detector returned %d results (cap %d) for %d×%d×%d input combinations",
			got, maxResults, N, N, N)
	}
}

// BenchmarkCartesianProductExplosion re-uses the same synthetic payload and
// ensures that Scanner.FromData finishes in reasonable time/allocs despite
// the N³ theoretical combination space.  This guards against accidental
// performance regressions that would re-introduce the Cartesian explosion.
func BenchmarkCartesianProductExplosion(b *testing.B) {
	tests := []struct {
		name      string
		uriCount  int
		userCount int
		passCount int
	}{
		{"Small_1x1x1", 1, 1, 1},
		{"Medium_5x5x5", 5, 5, 5},
		{"Large_10x10x10", 10, 10, 10},
		{"ManyURIs_15x5x5", 15, 5, 5},
		{"ManyUsers_5x15x5", 5, 15, 5},
		{"ManyPasswords_5x5x15", 5, 5, 15},
		{"Asymmetric_15x10x5", 15, 10, 5},
		{"VeryLarge_25x25x25", 25, 25, 25},
	}

	scanner := Scanner{}
	ctx := context.Background()

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			var sb strings.Builder

			for i := range tt.uriCount {
				sb.WriteString(fmt.Sprintf("ldap://host%d:389\n", i))
			}

			for i := range tt.userCount {
				letter := 'A' + rune(i%26)
				sb.WriteString(fmt.Sprintf(`bind="cn=user%c,dc=example,dc=org"`+"\n", letter))
			}

			for i := range tt.passCount {
				sb.WriteString(fmt.Sprintf(`pass="P@ssw0rd%02d"`+"\n", i))
			}

			payload := []byte(sb.String())

			b.ReportAllocs()
			b.ResetTimer()
			b.SetBytes(int64(len(payload)))

			for range b.N {
				if _, err := scanner.FromData(ctx, false, payload); err != nil {
					b.Fatalf("FromData error: %v", err)
				}
			}
		})
	}
}
