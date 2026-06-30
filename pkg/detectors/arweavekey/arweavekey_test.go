package arweavekey

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// fakeD is a synthetic 400-char base64url string used as a fake RSA private exponent.
// It is clearly artificial (all same character) and contains no real key material.
var fakeD = strings.Repeat("A", 400)

// fakeN is a synthetic 400-char base64url string used as a fake RSA modulus.
var fakeN = strings.Repeat("B", 400)

func TestArweaveKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - RSA JWK with long d field",
			input: `{"kty":"RSA","e":"AQAB","n":"` + fakeN + `","d":"` + fakeD + `"}`,
			want: []string{fakeD},
		},
		{
			name: "valid pattern - RSA JWK with spaces around colons",
			input: `{ "kty" : "RSA", "e" : "AQAB", "d" : "` + fakeD + `" }`,
			want: []string{fakeD},
		},
		{
			name: "valid pattern - arweave keyword with RSA JWK",
			input: `# arweave wallet
{"kty":"RSA","d":"` + fakeD + `"}`,
			want: []string{fakeD},
		},
		{
			name: "invalid pattern - EC key (kty=EC, no d field meaningful)",
			input: `{"kty":"EC","crv":"P-256","x":"` + fakeN + `","y":"` + fakeN + `"}`,
			want:  nil,
		},
		{
			name: "invalid pattern - RSA public key (kty=RSA but no d field)",
			input: `{"kty":"RSA","e":"AQAB","n":"` + fakeN + `"}`,
			want:  nil,
		},
		{
			name: "invalid pattern - d field too short (under 100 chars)",
			input: `{"kty":"RSA","d":"shortvalue"}`,
			want:  nil,
		},
		{
			name: "invalid pattern - no kty keyword and no arweave keyword",
			input: `{"e":"AQAB","n":"` + fakeN + `","d":"` + fakeD + `"}`,
			want:  nil,
		},
		{
			name: "invalid pattern - kty present but wrong value",
			input: `{"kty":"oct","k":"` + fakeD + `"}`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))

			if len(test.want) > 0 && len(matchedDetectors) == 0 {
				t.Errorf(
					"test %q failed: expected keywords %v to be found in the input",
					test.name,
					d.Keywords(),
				)
				return
			}

			results, err := d.FromData(
				context.Background(),
				false,
				[]byte(test.input),
			)
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf(
					"mismatch in result count: expected %d, got %d",
					len(test.want),
					len(results),
				)
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
