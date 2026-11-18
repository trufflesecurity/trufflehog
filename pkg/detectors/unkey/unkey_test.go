package unkey

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// Known vector from Unkey's key formatter. Not a live credential.
const fixtureKey = "unkey_111thX6Lunkeyv1ZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE18n8B8"

func TestUnkey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	second := rootKey("22222222" + "333333333333333333333333333333333333")
	if second == fixtureKey {
		t.Fatal("second synthetic key collided with the fixture")
	}

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - known vector",
			input: `UNKEY_ROOT_KEY=` + fixtureKey,
			want:  []string{fixtureKey},
		},
		{
			name:  "valid pattern - quoted",
			input: `token: "` + fixtureKey + `"`,
			want:  []string{fixtureKey},
		},
		{
			name:  "valid pattern - synthetic key",
			input: `export UNKEY_ROOT_KEY=` + second,
			want:  []string{second},
		},
		{
			name:  "finds all matches",
			input: "first " + fixtureKey + " second " + second,
			want:  []string{fixtureKey, second},
		},
		{
			name:  "duplicate key is reported once",
			input: fixtureKey + "\n" + fixtureKey,
			want:  []string{fixtureKey},
		},
		{
			name:  "invalid pattern - checksum mismatch",
			input: `UNKEY_ROOT_KEY=` + fixtureKey[:len(fixtureKey)-1] + "9",
			want:  nil,
		},
		{
			name:  "invalid pattern - excluded base58 character",
			input: `UNKEY_ROOT_KEY=unkey_011thX6Lunkeyv1ZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE18n8B8`,
			want:  nil,
		},
		{
			name:  "invalid pattern - user-facing prefix",
			input: `key=prod_sk_111thX6Lunkeyv1ZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE18n8B8`,
			want:  nil,
		},
		{
			name:  "invalid pattern - too short",
			input: `UNKEY_ROOT_KEY=unkey_111thX6Lunkeyv1ZfHDZZKUs92febYZhYRcXddmzfzF2`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords %v not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Fatalf("FromData error = %v", err)
			}

			if len(results) != len(test.want) {
				t.Fatalf("expected %d results, received %d", len(test.want), len(results))
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if r.Verified {
					t.Errorf("result verified = true, want false")
				}
				if err := r.VerificationError(); err != nil {
					t.Errorf("verification error = %v, want nil", err)
				}
				if r.SecretParts["key"] != string(r.Raw) {
					t.Errorf("SecretParts[key] = %q, want %q", r.SecretParts["key"], r.Raw)
				}
				actual[string(r.Raw)] = struct{}{}
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

func TestUnkey_VerifyFlagIsIgnored(t *testing.T) {
	d := Scanner{}
	input := []byte("root " + fixtureKey)

	for _, verify := range []bool{false, true} {
		results, err := d.FromData(context.Background(), verify, input)
		if err != nil {
			t.Fatalf("verify=%v error = %v", verify, err)
		}
		if len(results) != 1 {
			t.Fatalf("verify=%v got %d results, want 1", verify, len(results))
		}
		if results[0].Verified {
			t.Errorf("verify=%v verified = true, want false", verify)
		}
		if err := results[0].VerificationError(); err != nil {
			t.Errorf("verify=%v verification error = %v, want nil", verify, err)
		}
		if results[0].SecretParts["key"] != fixtureKey {
			t.Errorf("verify=%v SecretParts[key] = %q", verify, results[0].SecretParts["key"])
		}
	}
}

func TestChecksumKnownVector(t *testing.T) {
	unsigned := fixtureKey[:len(fixtureKey)-checksumLength]
	if got := checksum(unsigned); got != fixtureKey[len(fixtureKey)-checksumLength:] {
		t.Fatalf("checksum(%q) = %q, want %q", unsigned, got, fixtureKey[len(fixtureKey)-checksumLength:])
	}
	if !validChecksum(fixtureKey) {
		t.Fatal("fixture failed checksum validation")
	}
}

func TestEncodeBase58LeadingZeros(t *testing.T) {
	// Four big-endian bytes whose first three are zero encode as three '1's
	// plus the final byte. Alphabet index 1 is '2'.
	if got := encodeBase58([]byte{0, 0, 0, 1}); got != "1112" {
		t.Fatalf("encodeBase58 = %q, want %q", got, "1112")
	}
}

// rootKey builds a root key from 44 Base58 characters: 8 before the marker
// and 36 after it, then appends the checksum.
func rootKey(random string) string {
	if len(random) != 44 {
		panic("rootKey random length must be 44")
	}
	unsigned := "unkey_" + random[:8] + "unkeyv1" + random[8:]
	return unsigned + checksum(unsigned)
}

func TestRootKeyLength(t *testing.T) {
	key := rootKey(strings.Repeat("A", 44))
	if len(key) != 63 {
		t.Fatalf("len = %d, want 63", len(key))
	}
	if !keyPat.MatchString(key) {
		t.Fatalf("generated key did not match the pattern: %s", key)
	}
	if !validChecksum(key) {
		t.Fatal("generated key failed checksum validation")
	}
}
