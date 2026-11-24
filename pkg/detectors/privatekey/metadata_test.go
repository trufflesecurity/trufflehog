package privatekey

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/ssh"
)

// Keys are generated on each run rather than committed, so this file holds no
// private keys for other scanners to flag.
type testKeys struct {
	rsa2048, rsa3072                 *rsa.PrivateKey
	p224, p256, p384, p521           *ecdsa.PrivateKey
	ed25519                          ed25519.PrivateKey
	x25519                           *ecdh.PrivateKey
	opensshRSA, opensshEd25519       []byte // unencrypted, with a comment
	opensshRSAEncrypted              []byte // passphrase in the crack list
	opensshEd25519EncryptedStrong    []byte // passphrase not in the crack list
	legacyRSAEncrypted               []byte // passphrase in the crack list
	legacyECEncryptedStrong          []byte // passphrase not in the crack list
	crackablePass, uncrackablePass   []byte
	allPEMs                          map[string][]byte
	opensshRSAComment, opensshEdCmnt string
}

var getTestKeys = sync.OnceValue(func() *testKeys {
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	k := &testKeys{
		crackablePass:     passphrases[0],
		uncrackablePass:   []byte("not in the wordlist: 7d1f0c9e"),
		opensshRSAComment: "alice@build-box",
		opensshEdCmnt:     "deploy key for prod",
	}
	var err error
	k.rsa2048, err = rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	k.rsa3072, err = rsa.GenerateKey(rand.Reader, 3072)
	must(err)
	for _, c := range []struct {
		dst   **ecdsa.PrivateKey
		curve elliptic.Curve
	}{{&k.p224, elliptic.P224()}, {&k.p256, elliptic.P256()}, {&k.p384, elliptic.P384()}, {&k.p521, elliptic.P521()}} {
		*c.dst, err = ecdsa.GenerateKey(c.curve, rand.Reader)
		must(err)
	}
	_, k.ed25519, err = ed25519.GenerateKey(rand.Reader)
	must(err)
	k.x25519, err = ecdh.X25519().GenerateKey(rand.Reader)
	must(err)

	openssh := func(key crypto.PrivateKey, comment string) []byte {
		b, err := ssh.MarshalPrivateKey(key, comment)
		must(err)
		return pem.EncodeToMemory(b)
	}
	opensshEncrypted := func(key crypto.PrivateKey, pass []byte) []byte {
		b, err := ssh.MarshalPrivateKeyWithPassphrase(key, "comment is encrypted", pass)
		must(err)
		return pem.EncodeToMemory(b)
	}
	legacyEncrypted := func(typ string, der, pass []byte) []byte {
		//nolint:staticcheck // the legacy format is what is under test
		b, err := x509.EncryptPEMBlock(rand.Reader, typ, der, pass, x509.PEMCipherAES128)
		must(err)
		return pem.EncodeToMemory(b)
	}
	k.opensshRSA = openssh(k.rsa2048, k.opensshRSAComment)
	k.opensshEd25519 = openssh(k.ed25519, k.opensshEdCmnt)
	k.opensshRSAEncrypted = opensshEncrypted(k.rsa2048, k.crackablePass)
	k.opensshEd25519EncryptedStrong = opensshEncrypted(k.ed25519, k.uncrackablePass)
	k.legacyRSAEncrypted = legacyEncrypted("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k.rsa2048), k.crackablePass)
	p256DER, err := x509.MarshalECPrivateKey(k.p256)
	must(err)
	k.legacyECEncryptedStrong = legacyEncrypted("EC PRIVATE KEY", p256DER, k.uncrackablePass)

	k.allPEMs = map[string][]byte{
		"pkcs1 rsa":                     pemOf("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k.rsa2048)),
		"pkcs8 rsa":                     pkcs8(k.rsa3072),
		"pkcs8 p384":                    pkcs8(k.p384),
		"pkcs8 ed25519":                 pkcs8(k.ed25519),
		"pkcs8 x25519":                  pkcs8(k.x25519),
		"sec1 p224":                     sec1(k.p224),
		"sec1 p256":                     sec1(k.p256),
		"openssh rsa":                   k.opensshRSA,
		"openssh p521":                  openssh(k.p521, "ecdsa@host"),
		"openssh ed25519":               k.opensshEd25519,
		"openssh rsa encrypted":         k.opensshRSAEncrypted,
		"openssh ed25519 encrypted":     k.opensshEd25519EncryptedStrong,
		"legacy pkcs1 rsa encrypted":    k.legacyRSAEncrypted,
		"legacy sec1 p256 encrypted":    k.legacyECEncryptedStrong,
		"openssh ed25519 empty comment": openssh(k.ed25519, ""),
	}
	return k
})

func pemOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func pkcs8(key crypto.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pemOf("PRIVATE KEY", der)
}

func sec1(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pemOf("EC PRIVATE KEY", der)
}

// wantKey computes the expected metadata for a key independently of
// metadata.go: x/crypto's own fingerprint function, and fields given by hand.
func wantKey(t *testing.T, pub crypto.PublicKey, keyType string, bits int, curve, format string, extra map[string]string) map[string]string {
	t.Helper()
	want := map[string]string{
		"key_type":   keyType,
		"key_bits":   strconv.Itoa(bits),
		"key_format": format,
	}
	if curve != "" {
		want["curve"] = curve
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	want["spki_sha256"] = hex.EncodeToString(sum[:])
	if sshPub, err := ssh.NewPublicKey(pub); err == nil {
		want["public_key"] = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
		want["ssh_fingerprint"] = ssh.FingerprintSHA256(sshPub)
	}
	for k, v := range extra {
		want[k] = v
	}
	return want
}

func TestFromData_KeyMetadata(t *testing.T) {
	k := getTestKeys()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	opensshEncryption := map[string]string{
		"encrypted":             "true",
		"encryption_cipher":     "aes256-ctr",
		"encryption_kdf":        "bcrypt",
		"encryption_kdf_rounds": "16",
	}
	cracked := map[string]string{"cracked_encryption_passphrase": "true"}
	merge := func(ms ...map[string]string) map[string]string {
		out := map[string]string{}
		for _, m := range ms {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}

	tests := []struct {
		name string
		ctx  context.Context // canceled: an encrypted key is reported uncracked at once
		in   []byte
		want map[string]string
	}{
		{
			name: "rsa 2048 pkcs1",
			in:   k.allPEMs["pkcs1 rsa"],
			want: wantKey(t, &k.rsa2048.PublicKey, "rsa", 2048, "", "pkcs1", nil),
		},
		{
			name: "rsa 3072 pkcs8",
			in:   k.allPEMs["pkcs8 rsa"],
			want: wantKey(t, &k.rsa3072.PublicKey, "rsa", 3072, "", "pkcs8", nil),
		},
		{
			name: "rsa 2048 openssh with comment",
			in:   k.opensshRSA,
			want: wantKey(t, &k.rsa2048.PublicKey, "rsa", 2048, "", "openssh",
				map[string]string{"key_comment": k.opensshRSAComment}),
		},
		{
			name: "ecdsa p224 sec1 has no ssh encoding",
			in:   k.allPEMs["sec1 p224"],
			want: wantKey(t, &k.p224.PublicKey, "ecdsa", 224, "P-224", "sec1", nil),
		},
		{
			name: "ecdsa p256 sec1",
			in:   k.allPEMs["sec1 p256"],
			want: wantKey(t, &k.p256.PublicKey, "ecdsa", 256, "P-256", "sec1", nil),
		},
		{
			name: "ecdsa p384 pkcs8",
			in:   k.allPEMs["pkcs8 p384"],
			want: wantKey(t, &k.p384.PublicKey, "ecdsa", 384, "P-384", "pkcs8", nil),
		},
		{
			name: "ecdsa p521 openssh",
			in:   k.allPEMs["openssh p521"],
			want: wantKey(t, &k.p521.PublicKey, "ecdsa", 521, "P-521", "openssh",
				map[string]string{"key_comment": "ecdsa@host"}),
		},
		{
			name: "ed25519 openssh",
			in:   k.opensshEd25519,
			want: wantKey(t, k.ed25519.Public(), "ed25519", 256, "", "openssh",
				map[string]string{"key_comment": k.opensshEdCmnt}),
		},
		{
			name: "ed25519 openssh without comment",
			in:   k.allPEMs["openssh ed25519 empty comment"],
			want: wantKey(t, k.ed25519.Public(), "ed25519", 256, "", "openssh", nil),
		},
		{
			name: "openssh encrypted, cracked: comment stays encrypted",
			in:   k.opensshRSAEncrypted,
			want: wantKey(t, &k.rsa2048.PublicKey, "rsa", 2048, "", "openssh",
				merge(opensshEncryption, cracked)),
		},
		{
			name: "openssh encrypted, not cracked: public key read from the header",
			ctx:  canceled,
			in:   k.opensshEd25519EncryptedStrong,
			want: wantKey(t, k.ed25519.Public(), "ed25519", 256, "", "openssh", opensshEncryption),
		},
		{
			name: "legacy pem encrypted, cracked",
			in:   k.legacyRSAEncrypted,
			want: wantKey(t, &k.rsa2048.PublicKey, "rsa", 2048, "", "pkcs1",
				merge(cracked, map[string]string{"encrypted": "true", "encryption_cipher": "AES-128-CBC"})),
		},
		{
			name: "legacy pem encrypted, not cracked: only the container is known",
			ctx:  canceled,
			in:   k.legacyECEncryptedStrong,
			want: map[string]string{"encrypted": "true", "encryption_cipher": "AES-128-CBC", "key_format": "sec1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			results, err := Scanner{}.FromData(ctx, false, []byte("private key: "+string(tt.in)))
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 {
				t.Fatalf("got %d results, want 1", len(results))
			}
			if diff := cmp.Diff(tt.want, results[0].ExtraData); diff != "" {
				t.Errorf("ExtraData (-want +got):\n%s", diff)
			}
			checkPrintable(t, results[0].ExtraData)
		})
	}
}

// Ed25519 and X25519 keys in PKCS #8 are not reported by the detector today
// (FingerprintPEMKey does not accept them), but their metadata is still read
// correctly should that change.
func TestKeyMetadata_KeysTheDetectorDoesNotReport(t *testing.T) {
	k := getTestKeys()
	for _, tt := range []struct {
		name string
		in   []byte
		want map[string]string
	}{
		{"ed25519 pkcs8", k.allPEMs["pkcs8 ed25519"], wantKey(t, k.ed25519.Public(), "ed25519", 256, "", "pkcs8", nil)},
		{"x25519 pkcs8", k.allPEMs["pkcs8 x25519"], wantKey(t, k.x25519.PublicKey(), "x25519", 256, "", "pkcs8", nil)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ssh.ParseRawPrivateKey(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, keyMetadata(tt.in, parsed)); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

// Security-key (FIDO) OpenSSH keys are reported only when encrypted, because
// x/crypto cannot parse their private half; their type and public key come
// from the clear-text header. No tool here can make one without a hardware
// token, so the container is assembled by hand.
func TestFromData_EncryptedSecurityKeys(t *testing.T) {
	k := getTestKeys()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	p256Point, err := k.p256.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	encryptedWithPublicKey := func(pubWire []byte) []byte {
		kdf := ssh.Marshal(struct {
			Salt   string
			Rounds uint32
		}{string(make([]byte, 16)), 16})
		body := ssh.Marshal(struct {
			CipherName, KdfName, KdfOpts string
			NumKeys                      uint32
			PubKey, PrivKeyBlock         []byte
		}{"aes256-ctr", "bcrypt", string(kdf), 1, pubWire, make([]byte, 64)})
		return pemOf("OPENSSH PRIVATE KEY", append([]byte(privateKeyAuthMagic), body...))
	}
	encryption := map[string]string{
		"encrypted":             "true",
		"key_format":            "openssh",
		"encryption_cipher":     "aes256-ctr",
		"encryption_kdf":        "bcrypt",
		"encryption_kdf_rounds": "16",
	}

	for _, tt := range []struct {
		name, keyType, curve string
		pubWire              []byte
	}{
		{
			name: "ed25519-sk", keyType: "ed25519-sk",
			pubWire: ssh.Marshal(struct {
				Type string
				Key  []byte
				App  string
			}{ssh.KeyAlgoSKED25519, []byte(k.ed25519.Public().(ed25519.PublicKey)), "ssh:"}),
		},
		{
			name: "ecdsa-sk", keyType: "ecdsa-sk", curve: "P-256",
			pubWire: ssh.Marshal(struct {
				Type, Curve string
				Key         []byte
				App         string
			}{ssh.KeyAlgoSKECDSA256, "nistp256", p256Point, "ssh:"}),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := ssh.ParsePublicKey(tt.pubWire)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{
				"key_type":        tt.keyType,
				"key_bits":        "256",
				"public_key":      strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
				"ssh_fingerprint": ssh.FingerprintSHA256(pub),
			}
			if tt.curve != "" {
				want["curve"] = tt.curve
			}
			for k, v := range encryption {
				want[k] = v
			}

			results, err := Scanner{}.FromData(canceled, false, append([]byte("private key: "), encryptedWithPublicKey(tt.pubWire)...))
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 {
				t.Fatalf("got %d results, want 1", len(results))
			}
			if diff := cmp.Diff(want, results[0].ExtraData); diff != "" {
				t.Errorf("ExtraData (-want +got):\n%s", diff)
			}
		})
	}
}

// With verification on, a key no service recognizes used to lose all of its
// ExtraData; it now keeps what was read from the key. The canceled context
// makes every verification request fail before it is sent.
func TestFromData_VerifyKeepsKeyMetadata(t *testing.T) {
	k := getTestKeys()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := Scanner{}.FromData(ctx, true, []byte("private key: "+string(k.opensshEd25519)))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.Verified {
		t.Error("want unverified")
	}
	if r.VerificationError() == nil {
		t.Error("want a verification error from the canceled context")
	}
	want := wantKey(t, k.ed25519.Public(), "ed25519", 256, "", "openssh",
		map[string]string{"key_comment": k.opensshEdCmnt})
	if diff := cmp.Diff(want, r.ExtraData); diff != "" {
		t.Errorf("ExtraData (-want +got):\n%s", diff)
	}
}

func TestAddKeyMetadata_KeepsExistingValues(t *testing.T) {
	k := getTestKeys()
	extra := map[string]string{"key_type": "set by someone else", "encrypted": "true"}
	addKeyMetadata(extra, k.opensshEd25519, nil)
	if extra["key_type"] != "set by someone else" {
		t.Errorf("key_type overwritten: %q", extra["key_type"])
	}
	if extra["encrypted"] != "true" {
		t.Errorf("encrypted overwritten: %q", extra["encrypted"])
	}
	if extra["public_key"] == "" {
		t.Error("absent keys were not added")
	}

	addKeyMetadata(nil, k.opensshEd25519, nil) // must not panic
}

func TestKeyMetadata_CommentIsSanitized(t *testing.T) {
	k := getTestKeys()
	for _, tt := range []struct {
		name, comment, want string
	}{
		{"plain", "bob@laptop", "bob@laptop"},
		{"terminal escapes and bidi override", "\x1b[2J\x07pwned\u202egnp.exe", "[2Jpwnedgnp.exe"},
		{"invalid utf-8", "bad\xff\xfeutf8", "bad\uFFFD" + "utf8"},
		{"nul bytes", "a\x00b", "ab"},
		{"long", strings.Repeat("a", 10000), strings.Repeat("a", maxCommentLen)},
		{"long multibyte", strings.Repeat("\u00e9", 5000), strings.Repeat("\u00e9", maxCommentLen)},
		{"only whitespace", "  \t ", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ssh.MarshalPrivateKey(k.ed25519, tt.comment)
			if err != nil {
				t.Fatal(err)
			}
			in := pem.EncodeToMemory(b)
			parsed, err := ssh.ParseRawPrivateKey(in)
			if err != nil {
				t.Fatal(err)
			}
			md := keyMetadata(in, parsed)
			got, ok := md["key_comment"]
			if tt.want == "" && ok {
				t.Errorf("want no key_comment, got %q", got)
			} else if got != tt.want {
				t.Errorf("key_comment = %q, want %q", got, tt.want)
			}
			checkPrintable(t, md)
		})
	}
}

// Malformed keys and impossible parsed values must yield less metadata, never
// a panic. keyMetadata is called directly so that a panic is not hidden by
// addKeyMetadata's recover.
func TestKeyMetadata_MalformedInput(t *testing.T) {
	k := getTestKeys()
	magic := []byte(privateKeyAuthMagic)
	opensshBody := func(fields ...any) []byte {
		var b []byte
		for _, f := range fields {
			b = append(b, ssh.Marshal(f)...)
		}
		return pemOf("OPENSSH PRIVATE KEY", append(append([]byte{}, magic...), b...))
	}
	type header struct {
		CipherName, KdfName, KdfOpts string
		NumKeys                      uint32
		PubKey, PrivKeyBlock         []byte
	}
	ed := ssh.Marshal(struct {
		Name string
		Key  []byte
	}{ssh.KeyAlgoED25519, make([]byte, 32)})

	pems := map[string][]byte{
		"nil":                      nil,
		"empty":                    {},
		"not pem":                  []byte("private key but no pem here"),
		"unknown pem type":         pemOf("FOO PRIVATE KEY", []byte("whatever")),
		"empty openssh":            pemOf("OPENSSH PRIVATE KEY", nil),
		"openssh magic only":       pemOf("OPENSSH PRIVATE KEY", magic),
		"openssh wrong magic":      pemOf("OPENSSH PRIVATE KEY", []byte("openssh-key-v2\x00rest")),
		"openssh huge length":      pemOf("OPENSSH PRIVATE KEY", append(append([]byte{}, magic...), 0xff, 0xff, 0xff, 0xff)),
		"openssh two keys":         opensshBody(header{"none", "none", "", 2, ed, nil}),
		"openssh garbage pubkey":   opensshBody(header{"aes256-ctr", "bcrypt", "x", 1, []byte("garbage"), nil}),
		"openssh garbage kdf opts": opensshBody(header{"aes256-ctr", "bcrypt", "\x00\x00\x00\x10short", 1, ed, nil}),
		"openssh garbage block":    opensshBody(header{"none", "none", "", 1, ed, []byte("\x00\x00\x00\x01\x00\x00\x00\x01")}),
		"openssh unknown key type": opensshBody(header{"none", "none", "", 1, ed, ssh.Marshal(struct {
			C1, C2 uint32
			T      string
		}{1, 1, "ssh-unknown"})}),
		"openssh hostile cipher name": opensshBody(header{"\x1b]0;owned\x07" + strings.Repeat("\xff", 5000), "\x00", "", 1, ed, nil}),
		"legacy encrypted no dek-info": pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte("x"),
		}),
		"legacy encrypted hostile dek-info": pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "\x1b[31m" + strings.Repeat("A", 4000)}, Bytes: []byte("x"),
		}),
	}
	ed25519Short := ed25519.PrivateKey(make([]byte, 10))
	parsedKeys := map[string]any{
		"nil":                     nil,
		"string":                  "not a key",
		"nil rsa":                 (*rsa.PrivateKey)(nil),
		"empty rsa":               &rsa.PrivateKey{},
		"nil ecdsa":               (*ecdsa.PrivateKey)(nil),
		"empty ecdsa":             &ecdsa.PrivateKey{},
		"ecdsa without point":     &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}},
		"short ed25519":           ed25519Short,
		"short ed25519 pointer":   &ed25519Short,
		"nil ed25519 pointer":     (*ed25519.PrivateKey)(nil),
		"nil ecdh":                (*ecdh.PrivateKey)(nil),
		"public key, not private": k.ed25519.Public(),
		"rsa public key":          &k.rsa2048.PublicKey,
	}

	for pemName, in := range pems {
		for keyName, parsed := range parsedKeys {
			t.Run(pemName+"/"+keyName, func(t *testing.T) {
				checkPrintable(t, keyMetadata(in, parsed))
			})
		}
	}

	t.Run("impossible parsed keys yield nothing", func(t *testing.T) {
		for name, parsed := range parsedKeys {
			if md := keyMetadata(nil, parsed); len(md) != 0 {
				t.Errorf("%s: got %v", name, md)
			}
		}
	})

	t.Run("garbage embedded public key is skipped", func(t *testing.T) {
		md := keyMetadata(pems["openssh garbage pubkey"], nil)
		for _, key := range []string{"key_type", "public_key", "ssh_fingerprint"} {
			if v, ok := md[key]; ok {
				t.Errorf("%s = %q", key, v)
			}
		}
		if md["encryption_kdf"] != "bcrypt" || md["encryption_cipher"] != "aes256-ctr" {
			t.Errorf("readable header fields lost: %v", md)
		}
	})

	t.Run("hostile header values are cleaned", func(t *testing.T) {
		md := keyMetadata(pems["openssh hostile cipher name"], nil)
		if got, want := md["encryption_cipher"], "]0;owned\uFFFD"; got != want {
			t.Errorf("encryption_cipher = %q, want %q", got, want)
		}
		if v, ok := md["encryption_kdf"]; ok {
			t.Errorf("a KDF name of only control characters was kept: %q", v)
		}
		md = keyMetadata(pems["legacy encrypted hostile dek-info"], nil)
		if got, want := md["encryption_cipher"], "[31m"+strings.Repeat("A", maxNameLen-4); got != want {
			t.Errorf("encryption_cipher = %q, want %q", got, want)
		}
	})
}

// Every truncation and every single-bit flip of each test key must be handled:
// FromData may drop the key or report less, but must not panic or emit
// unprintable metadata.
func TestFromData_CorruptedKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	k := getTestKeys()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // report encrypted mutants without trying the wordlist

	for name, in := range k.allPEMs {
		block, _ := pem.Decode(in)
		mutants := make([][]byte, 0, 2*len(block.Bytes))
		for n := range block.Bytes {
			mutants = append(mutants, pem.EncodeToMemory(&pem.Block{Type: block.Type, Headers: block.Headers, Bytes: block.Bytes[:n]}))
		}
		for i := range block.Bytes {
			flipped := append([]byte{}, block.Bytes...)
			flipped[i] ^= 1 << (i % 8)
			mutants = append(mutants, pem.EncodeToMemory(&pem.Block{Type: block.Type, Headers: block.Headers, Bytes: flipped}))
		}
		t.Run(name, func(t *testing.T) {
			for _, m := range mutants {
				results, err := Scanner{}.FromData(ctx, false, append([]byte("private key: "), m...))
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range results {
					checkPrintable(t, r.ExtraData)
				}
				if parsed, err := ssh.ParseRawPrivateKey(m); err == nil {
					checkPrintable(t, keyMetadata(m, parsed))
				}
			}
		})
	}
}

func FuzzKeyMetadata(f *testing.F) {
	for _, in := range getTestKeys().allPEMs {
		f.Add(in)
	}
	f.Add([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n"))
	f.Add([]byte("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		checkPrintable(t, keyMetadata(in, nil))
		if parsed, err := ssh.ParseRawPrivateKey(in); err == nil {
			checkPrintable(t, keyMetadata(in, parsed))
		}
	})
}

// checkPrintable fails if any value could not be stored in a protobuf string
// or would put control characters on a terminal.
func checkPrintable(t *testing.T, md map[string]string) {
	t.Helper()
	for k, v := range md {
		if !utf8.ValidString(v) {
			t.Errorf("%s: invalid UTF-8: %q", k, v)
		}
		if strings.IndexFunc(v, func(r rune) bool { return unicode.In(r, unicode.Cc, unicode.Cf) }) >= 0 {
			t.Errorf("%s: control or format character: %q", k, v)
		}
		if v == "" {
			t.Errorf("%s: empty value", k)
		}
	}
}

// fakeRSAPublicKey is an SSH RSA public key with a modulus of the given size.
// Only its encoding is used, so the modulus need not be a product of primes.
func fakeRSAPublicKey(t *testing.T, bits int) ssh.PublicKey {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.SetBit(n, 0, 1)
	pub, err := ssh.NewPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestDescribeSSHEncoding_LeavesOutHugePublicKeys(t *testing.T) {
	for _, tt := range []struct {
		bits          int
		wantPublicKey bool
	}{
		{2048, true},
		{4096, true},
		{5880, true}, // the largest RSA modulus whose line fits maxPublicKeyLen
		{8192, false},
		{16384, false},
	} {
		t.Run(strconv.Itoa(tt.bits), func(t *testing.T) {
			md := map[string]string{}
			describeSSHEncoding(md, fakeRSAPublicKey(t, tt.bits))
			if _, ok := md["public_key"]; ok != tt.wantPublicKey {
				t.Errorf("public_key present = %v, want %v (line length %d)", ok, tt.wantPublicKey, len(md["public_key"]))
			}
			if md["ssh_fingerprint"] == "" {
				t.Error("ssh_fingerprint missing")
			}
		})
	}
}

// Whatever a key holds, the metadata stays small enough that it cannot push a
// result's ExtraData past size limits downstream stores enforce (TruffleHog
// Enterprise refuses extra_data over 8192 characters).
func TestKeyMetadata_SizeIsBounded(t *testing.T) {
	const budget = 2048 // characters of JSON, as downstream stores count them

	pub := fakeRSAPublicKey(t, 5880).Marshal()
	huge := strings.Repeat("é", 10000)
	header := func(cipher, kdf string, block []byte) []byte {
		body := ssh.Marshal(struct {
			CipherName, KdfName, KdfOpts string
			NumKeys                      uint32
			PubKey, PrivKeyBlock         []byte
		}{cipher, kdf, "", 1, pub, block})
		return pemOf("OPENSSH PRIVATE KEY", append([]byte(privateKeyAuthMagic), body...))
	}
	// An unencrypted RSA private section whose fields are junk but whose
	// layout is right, so the comment after them is read.
	unencryptedBlock := ssh.Marshal(struct {
		Check1, Check2      uint32
		Keytype             string
		N, E, D, Iqmp, P, Q []byte
		Comment             string
	}{7, 7, ssh.KeyAlgoRSA, []byte{1}, []byte{3}, []byte{1}, []byte{1}, []byte{1}, []byte{1}, huge})

	for name, in := range map[string][]byte{
		"encrypted, huge cipher and KDF names": header(huge, huge, make([]byte, 64)),
		"unencrypted, huge comment":            header("none", "none", unencryptedBlock),
	} {
		t.Run(name, func(t *testing.T) {
			md := keyMetadata(in, nil)
			if md["public_key"] == "" || md["key_type"] != "rsa" {
				t.Fatalf("expected the full set of fields to be measured, got %v", md)
			}
			// What the detector itself adds next to the metadata.
			md["encrypted"] = "true"
			md["cracked_encryption_passphrase"] = "true"
			b, err := json.Marshal(md)
			if err != nil {
				t.Fatal(err)
			}
			if n := utf8.RuneCount(b); n > budget {
				t.Errorf("metadata is %d characters of JSON, budget %d", n, budget)
			} else {
				t.Logf("metadata is %d characters of JSON", n)
			}
		})
	}
}
