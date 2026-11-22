package privatekey

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
-----END RSA PRIVATE KEY-----
`
	invalidPattern = `-----BEGIN?RSA?PRIVATE?KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
-----END RSA PRIVATE KEY-----`
	keyword = "privatekey"
)

func TestPrivatekey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword privatekey",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s = '%s'", keyword, invalidPattern),
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

// encryptedUncrackablePattern is an ed25519 key protected by a passphrase that
// is not present in the built-in wordlist (pkg/detectors/privatekey/list.txt),
// so Crack cannot recover it.
var encryptedUncrackablePattern = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDnvQyInG
vB+yh/WYczTGXbAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILUSv84lMSLVN0iP
knFlHoYobo1oohtLNp/ihBaf76QxAAAAoErDjg2HQs1hgYm0vfyrpBxWrcJ1u/LQG4o6cm
GJ3NnZmMmJemrnMXjGHB3zj63AEPxxyb6BWZH5Olb5gYMgWcnOU91cGvyC7aT6C5cOnFb1
ZtkdxTxqeUOMFS51gwDT04aURSz/caCV9KN4Y2MCHyW+GWxxD7eL0R6KhyT2j0z2BewCw9
kRN1fq3C2rTb+wTaNz8q9X0R+6JGxfXGhpTJ0=
-----END OPENSSH PRIVATE KEY-----
`

// TestPrivatekey_EncryptedKeyReported asserts that a passphrase-protected key
// whose passphrase cannot be cracked is still surfaced as an unverified finding
// rather than being dropped silently (issue #5115).
func TestPrivatekey_EncryptedKeyReported(t *testing.T) {
	d := Scanner{}
	input := fmt.Sprintf("%s = '%s'", keyword, encryptedUncrackablePattern)

	results, err := d.FromData(context.Background(), false, []byte(input))
	if err != nil {
		t.Fatalf("FromData error = %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result for an encrypted key with an uncrackable passphrase, got %d", len(results))
	}

	r := results[0]
	if r.Verified {
		t.Errorf("expected the finding to be unverified")
	}
	if r.VerificationError() == nil {
		t.Errorf("expected a verification error to be set on the finding")
	}
	if r.ExtraData["encrypted"] != "true" {
		t.Errorf("expected ExtraData[\"encrypted\"] = \"true\", got %q", r.ExtraData["encrypted"])
	}
}

// encryptedCrackablePattern is an EC key protected by "password", which is in
// the built-in wordlist. Legacy PEM encryption keeps each attempt cheap.
var encryptedCrackablePattern = `-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,B6689D621B49C41D88EF97914CA74446

OnWuhQ0uWK1l6Tjsqas0lfqDPSavVWMV3fqedzz1xkN8Xm6zSQ1FxGE1J68vNS2e
pLKZTu94oU284bJVdTpRKwTaB76WKlIWu3474kUojgTNTvL4O0XPp9j3bXiV+ocS
nriFCO9Sv2mOkjjUt5JcL1PscuYkL2bqK3gtCaJ0COg=
-----END EC PRIVATE KEY-----
`

// stubVerifyKey replaces the network checks for the length of a test.
func stubVerifyKey(t *testing.T, stub func(ctx context.Context, fingerprint string) (map[string]string, []string)) {
	t.Helper()
	original := verifyKey
	verifyKey = func(ctx context.Context, _ any, fingerprint string, _ bool) (map[string]string, []string) {
		return stub(ctx, fingerprint)
	}
	t.Cleanup(func() { verifyKey = original })
}

// TestPrivatekey_PlainKeyVerifiedBeforeEncryptedKeyIsCracked asserts that an
// encrypted key earlier in a chunk cannot use up the time a plain key needs to
// be verified (issue #5563). The stub ends the context after the first key is
// verified, standing in for cracking that outlasts the detector timeout.
func TestPrivatekey_PlainKeyVerifiedBeforeEncryptedKeyIsCracked(t *testing.T) {
	plain, err := Scanner{}.FromData(context.Background(), false, []byte(validPattern))
	if err != nil || len(plain) != 1 {
		t.Fatalf("FromData on the plain key = %d results, error %v", len(plain), err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var verified []string
	stubVerifyKey(t, func(ctx context.Context, fingerprint string) (map[string]string, []string) {
		if err := ctx.Err(); err != nil {
			t.Errorf("verification started with a done context: %v", err)
		}
		verified = append(verified, fingerprint)
		cancel()
		return map[string]string{"github_user": "octocat"}, nil
	})

	input := fmt.Sprintf("%s\n%s", encryptedCrackablePattern, validPattern)
	results, err := Scanner{}.FromData(ctx, true, []byte(input))
	if err != nil {
		t.Fatalf("FromData error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if len(verified) != 1 {
		t.Fatalf("expected 1 key to reach verification, got %d", len(verified))
	}

	encryptedKey, plainKey := results[0], results[1]

	if string(plainKey.Raw) != string(plain[0].Raw) {
		t.Fatalf("expected results in the order the keys appear, with the plain key second")
	}
	if !plainKey.Verified || plainKey.ExtraData["github_user"] != "octocat" {
		t.Errorf("expected the plain key to be verified, got Verified = %v, ExtraData = %v", plainKey.Verified, plainKey.ExtraData)
	}
	if err := plainKey.VerificationError(); err != nil {
		t.Errorf("expected no verification error on the plain key, got %v", err)
	}

	// Crack stops between attempts once the context is done, so the encrypted
	// key is still reported, uncracked, with the context error as the reason.
	if encryptedKey.Verified {
		t.Errorf("expected the encrypted key to be unverified")
	}
	if err := encryptedKey.VerificationError(); err == nil || err.Error() != context.Canceled.Error() {
		t.Errorf("verification error on the encrypted key = %v, want %q", err, context.Canceled)
	}
	if encryptedKey.ExtraData["encrypted"] != "true" || encryptedKey.ExtraData["cracked_encryption_passphrase"] != "" {
		t.Errorf("expected the encrypted key to be reported uncracked, got ExtraData = %v", encryptedKey.ExtraData)
	}
}

// newPlainKey returns a freshly generated, unencrypted EC key in PEM form.
func newPlainKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("encoding key: %v", err)
	}
	return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
}

// TestPrivatekey_PlainKeysVerifiedSideBySide asserts that the plain keys of a
// chunk are verified up to maxConcurrentVerifications at a time instead of one
// after another, which is what let a long run of keys outlast the detector
// timeout (issue #5563). Each stubbed verification holds until that many are
// in flight.
func TestPrivatekey_PlainKeysVerifiedSideBySide(t *testing.T) {
	keys := make([]string, maxConcurrentVerifications+2)
	for i := range keys {
		keys[i] = newPlainKey(t)
	}

	var (
		mu       sync.Mutex
		inFlight int
		peak     int
		full     = make(chan struct{})
	)
	stubVerifyKey(t, func(context.Context, string) (map[string]string, []string) {
		mu.Lock()
		inFlight++
		if inFlight > peak {
			peak = inFlight
		}
		if inFlight == maxConcurrentVerifications {
			select {
			case <-full:
			default:
				close(full)
			}
		}
		mu.Unlock()

		select {
		case <-full:
		case <-time.After(5 * time.Second):
			t.Error("a key waited for another key's verification to finish")
		}

		mu.Lock()
		inFlight--
		mu.Unlock()
		return nil, nil
	})

	results, err := Scanner{}.FromData(context.Background(), true, []byte(strings.Join(keys, "\n")))
	if err != nil {
		t.Fatalf("FromData error = %v", err)
	}
	if len(results) != len(keys) {
		t.Fatalf("expected %d results, got %d", len(keys), len(results))
	}
	for i, key := range keys {
		if string(results[i].Raw) != Normalize(key) {
			t.Fatalf("result %d is not the key at position %d: results are out of order", i, i)
		}
	}
	if peak != maxConcurrentVerifications {
		t.Errorf("most keys verified at once = %d, want %d", peak, maxConcurrentVerifications)
	}
}

// TestPrivatekey_NotVerifiedOnceContextIsDone asserts that a key whose turn
// comes after the deadline is reported as not verified, without dialing out
// and collecting errors that read like a network outage (issue #5563).
func TestPrivatekey_NotVerifiedOnceContextIsDone(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	stubVerifyKey(t, func(context.Context, string) (map[string]string, []string) {
		t.Error("verification ran with a done context")
		return nil, nil
	})

	results, err := Scanner{}.FromData(ctx, true, []byte(validPattern))
	if err != nil {
		t.Fatalf("FromData error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verified {
		t.Errorf("expected the finding to be unverified")
	}
	want := fmt.Sprintf("%s: %v", notVerifiedMessage, context.DeadlineExceeded)
	if err := results[0].VerificationError(); err == nil || err.Error() != want {
		t.Errorf("verification error = %v, want %q", err, want)
	}
}
