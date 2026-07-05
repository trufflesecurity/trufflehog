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

// Field sizes of a real 4096-bit Arweave wallet keyfile: n and d are ~683
// base64url chars (512 bytes), the CRT params p/q/dp/dq/qi are ~342 chars
// (256 bytes) each.
var (
	fullN  = strings.Repeat("N", 683)
	fullD  = strings.Repeat("D", 683)
	fullP  = strings.Repeat("P", 342)
	fullQ  = strings.Repeat("Q", 342)
	fullDP = strings.Repeat("E", 342)
	fullDQ = strings.Repeat("F", 342)
	fullQI = strings.Repeat("G", 342)
)

func TestArweaveKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - RSA JWK with long d field",
			input: `{"kty":"RSA","e":"AQAB","n":"` + fakeN + `","d":"` + fakeD + `"}`,
			want:  []string{fakeD},
		},
		{
			name:  "valid pattern - RSA JWK with spaces around colons",
			input: `{ "kty" : "RSA", "e" : "AQAB", "d" : "` + fakeD + `" }`,
			want:  []string{fakeD},
		},
		{
			name: "valid pattern - arweave keyword with RSA JWK",
			input: `# arweave wallet
{"kty":"RSA","d":"` + fakeD + `"}`,
			want: []string{fakeD},
		},
		{
			name:  "invalid pattern - EC key (kty=EC, no d field meaningful)",
			input: `{"kty":"EC","crv":"P-256","x":"` + fakeN + `","y":"` + fakeN + `"}`,
			want:  nil,
		},
		{
			name:  "invalid pattern - RSA public key (kty=RSA but no d field)",
			input: `{"kty":"RSA","e":"AQAB","n":"` + fakeN + `"}`,
			want:  nil,
		},
		{
			name:  "invalid pattern - d field too short (under 100 chars)",
			input: `{"kty":"RSA","d":"shortvalue"}`,
			want:  nil,
		},
		{
			name:  "invalid pattern - no kty keyword and no arweave keyword",
			input: `{"e":"AQAB","n":"` + fakeN + `","d":"` + fakeD + `"}`,
			want:  nil,
		},
		{
			name:  "invalid pattern - kty present but wrong value",
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

// TestArweaveKey_EngineSpanExtraction runs the detector through the engine's
// Aho-Corasick span calculator rather than calling FromData with the full
// input. A full-size Arweave keyfile places the end of the "d" value well
// beyond the engine's default 512-byte window after the "kty" keyword, so
// this test fails unless the Scanner implements MaxSecretSizeProvider with a
// large enough window.
func TestArweaveKey_EngineSpanExtraction(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	// Field order matches arweave-generated keyfiles (kty first, d after n).
	jwk := `{"kty":"RSA","n":"` + fullN + `","e":"AQAB","d":"` + fullD +
		`","p":"` + fullP + `","q":"` + fullQ + `","dp":"` + fullDP +
		`","dq":"` + fullDQ + `","qi":"` + fullQI + `"}`
	payload := "config dump start\n" + jwk + "\nconfig dump end\n"

	// Sanity-check the fixture: the "d" value must end more than 512 bytes
	// after the "kty" keyword, otherwise this test would pass even with the
	// engine's default window, and the JWK must fit in the declared window.
	ktyIdx := strings.Index(payload, "kty")
	dEnd := strings.Index(payload, fullD) + len(fullD) + 1
	require.Greater(t, dEnd-ktyIdx, 512)
	require.GreaterOrEqual(t, d.MaxSecretSize(), int64(len(jwk)))

	matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(payload))
	require.NotEmpty(t, matchedDetectors)

	// Feed the extracted spans to FromData the same way the engine does.
	found := false
	for _, match := range matchedDetectors {
		for _, matchBytes := range match.Matches() {
			results, err := d.FromData(context.Background(), false, matchBytes)
			require.NoError(t, err)
			for _, r := range results {
				if string(r.Raw) == fullD {
					found = true
				}
			}
		}
	}
	require.True(t, found, "private exponent was truncated by the engine's span extraction")
}
