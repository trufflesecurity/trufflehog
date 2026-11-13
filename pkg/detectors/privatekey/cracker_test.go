//go:build detectors
// +build detectors

// The tests in this file run only with -tags=detectors (make test-detectors);
// the default go test build excludes the whole file.

package privatekey

import (
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

var (
	testEncryptedKeyCorrectPassword   = []byte("123456")
	testEncryptedKeyIncorrectPassword = []byte("incorrect")
	testEncryptedKey                  = []byte(Normalize(`-----BEGIN OPENSSH PRIVATE KEY-----
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
Hx7UPVlTK8dyvk1Z+Yw0nrfNClI=
-----END OPENSSH PRIVATE KEY-----`))

	// testDefaultKDFKey and testExpensiveKDFKey are ed25519 keys protected
	// with the same passphrase as testEncryptedKeyCorrectPassword at bcrypt
	// round counts of 16 (OpenSSH's default) and 300, generated with
	// ssh-keygen -a.
	testDefaultKDFKey = []byte(Normalize(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDGWhRIOR
LWaktgbL8r3S5jAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIHqefEc52RY6n1ej
6vEPvbPvprG0m5OT5BAFtdFLdyJQAAAAwFsqIS4QNeZJOQTxTDpQBXYvb3bI+PXmTHlaak
BXlCR0Qxk/mmAbL4GheuqnqHxJCGGDU9n5+aaK9ZEgJv+fpv5ahanIm/wgRjn8q9mZSk2r
QhGklYrkJV6zkXYVBH7VdP3rHSlCjuziQeKDhxiCTlfeyUfb5O5Tx12TBAo6ADTk76L7+0
Y+NPIDr2X5m+fWBMI4XFuQPmmSEm28gV5IERrMUc9zGnS7fJ4xHbtySJoF3wWUlEBrTGDb
HCRHIpLSoA==
-----END OPENSSH PRIVATE KEY-----`))
	testExpensiveKDFKey = []byte(Normalize(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDiegbnWk
wjBR6lL750YpD8AAABLAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIFPdyzxAY2IvJCsy
RSK0vvQAM+Ow+zdR+U0tf5jJWpdsAAAAwBrWAmdHm4xKSeMsj+rXp+LWgXMpYj9ZYWNJnC
VGMvU81m8gj78dNmjB8U+J3Ns6jmKXNicnwGHHZ9BVCimlnsiGgpp44ZhxSAYqNJV+CoUY
FphHKrN68miEiSWFRuZsKB2Xjz3B3a+ApdCrgK9/+0k1finNMzOEpTdmSvkQTP/fLeiqoC
m/aSusJwO1NAZDcuyty6pMCKygw6ENqGZf1uyMf+KQwJq3JXwgbRAprb3tBrIEAEEkD4mA
ppGpPzMyWA==
-----END OPENSSH PRIVATE KEY-----`))

	// testKeyAtCap and testKeyPastCap are ed25519 keys with the same
	// passphrase at bcrypt round counts of exactly 256 (maxCrackRounds) and
	// 257 (one past it), generated with ssh-keygen -a.
	testKeyAtCap = []byte(Normalize(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDLe9Hn5/
Qgs+VcI7Z2oHt0AAABAAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJ14+tRTYMsqi2CF
AEETEztjC3N8MwGDhDtcJ9ER4f6pAAAAwPwxz4us6d80EoZeKaAGdqhdK5g1yOLuTFiemC
ECwotCzi2W+lk7m9tHgyvbKUyg+dldDP5dlnwberSmmy+OMrJkVVw2PeX5yr6lCcuHZXHq
Eqoo7oSlsmlaBpIC/I12JkGQxg6Pv13iIhIyPigUWA3myzAoAc+0Wtluta/qAK+nf5B6ar
f57dBJ3uVeU8E3U/UDiJhwVdJnCslkGGWgM65ECvcFZu65DNhoVnFWtsBe2Uom48hG46Cf
3NkF0FXQpA==
-----END OPENSSH PRIVATE KEY-----`))
	testKeyPastCap = []byte(Normalize(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABANsc+iFh
yaFTnsMn8tAEn4AAABAQAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAINIGnk11f1Mup1Bh
oMiwh/wisUHuDWOygxhq0PSz+HTSAAAAwOcoRpUbj4YGrNVTvE6Ve5913vgQkAZ8pCBHgk
AMjTSVXykiRgK2/7t8k7gPmb1F7QUaiLS0W5X49QeuwYQVihmCSKlupZTWmqozipWlkXSG
ACFqnWvE0jURRZd76qBwrtFfyZb24V6LVws/nz0RARXYG+tn8KW3xsjqhvpfLY5KUwLN1j
uWqgiel/xeC/UZZiPt9egS6AS9Orn2yaGP882HzMXAsWPIUcslgYxEEjE1FRCaf8YtvCw+
rZea5gQDRQ==
-----END OPENSSH PRIVATE KEY-----`))
)

func Test_crack(t *testing.T) {
	tests := []struct {
		name             string
		in               []byte
		wantedPassphrase string
		wantErr          bool
	}{
		{
			name:             "crackable",
			wantErr:          false,
			in:               testEncryptedKey,
			wantedPassphrase: string(testEncryptedKeyCorrectPassword),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, passphrase, err := Crack(context.Background(), tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("crack() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if passphrase != string(tt.wantedPassphrase) {
				t.Errorf("crack() passphrase = %v, want %v", passphrase, string(testEncryptedKeyCorrectPassword))
			}
		})
	}
}

// Test_crack_stops_when_context_done asserts that a done context stops the
// passphrase list instead of running it to completion: a wrong passphrase
// costs a full KDF run, so the list walk must check between attempts.
func Test_crack_stops_when_context_done(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := Crack(ctx, testEncryptedKey)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if errors.Is(err, ErrUncrackable) {
		t.Error("expected the done context to stop the passphrase list, not run it to completion")
	}
}

// Test_crack_skips_kdf_above_cap asserts that a key whose KDF is harder than
// the crack budget is refused without attempting any passphrase. The key is
// legal for x/crypto, whose own ceiling is 2048 rounds, so an error here comes
// from the detector's cap rather than the library.
func Test_crack_skips_kdf_above_cap(t *testing.T) {
	_, _, err := Crack(context.Background(), testExpensiveKDFKey)
	if !errors.Is(err, ErrKDFTooExpensive) {
		t.Errorf("expected ErrKDFTooExpensive, got %v", err)
	}
}

// sshString length-prefixes s the way the OpenSSH wire format does.
func sshString(s []byte) []byte {
	out := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(out, uint32(len(s)))
	copy(out[4:], s)
	return out
}

// Test_crack_bypass_options_fails_closed crafts a key whose bcrypt options
// blob is salt || rounds || trailing bytes. x/crypto parses that blob by
// ignoring the trailing bytes, so a round count read from the blob's tail
// would see 1 instead of 2048 and let a hardened key past the cap. The strict
// shape check fails closed: the crafted key is refused like any other
// over-cap key.
func Test_crack_bypass_options_fails_closed(t *testing.T) {
	block, _ := pem.Decode(testDefaultKDFKey)
	if block == nil {
		t.Fatal("fixture key did not decode")
	}
	optsStart := len(opensshMagic) + (4 + len("aes256-ctr")) + (4 + len("bcrypt"))
	optsLen := int(binary.BigEndian.Uint32(block.Bytes[optsStart : optsStart+4]))
	salt := append([]byte{}, block.Bytes[optsStart+4:optsStart+4+optsLen-4]...)

	craftedOpts := append(salt, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01)
	body := append([]byte{}, block.Bytes[:optsStart]...)
	body = append(body, sshString(craftedOpts)...)
	body = append(body, block.Bytes[optsStart+4+optsLen:]...)
	crafted := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: body})

	_, _, err := Crack(context.Background(), crafted)
	if !errors.Is(err, ErrKDFTooExpensive) {
		t.Errorf("expected ErrKDFTooExpensive for options with trailing bytes, got %v", err)
	}
}

// Test_crack_round_cap_boundary pins the cap on both sides: a key at exactly
// maxCrackRounds still cracks, and one round past it is refused.
func Test_crack_round_cap_boundary(t *testing.T) {
	_, passphrase, err := Crack(context.Background(), testKeyAtCap)
	if err != nil {
		t.Errorf("expected the %d-round key to crack, got %v", maxCrackRounds, err)
	}
	if passphrase != string(testEncryptedKeyCorrectPassword) {
		t.Errorf("passphrase = %q, want %q", passphrase, string(testEncryptedKeyCorrectPassword))
	}

	if _, _, err := Crack(context.Background(), testKeyPastCap); !errors.Is(err, ErrKDFTooExpensive) {
		t.Errorf("expected ErrKDFTooExpensive for a %d-round key, got %v", maxCrackRounds+1, err)
	}
}

func Test_opensshBcryptRounds(t *testing.T) {
	tests := []struct {
		name   string
		key    []byte
		rounds uint32
		ok     bool
	}{
		{
			name:   "OpenSSH default rounds",
			key:    testDefaultKDFKey,
			rounds: 16,
			ok:     true,
		},
		{
			name:   "high rounds",
			key:    testExpensiveKDFKey,
			rounds: 300,
			ok:     true,
		},
		{
			name: "plain PEM key",
			key:  []byte("-----BEGIN RSA PRIVATE KEY-----\nnope\n-----END RSA PRIVATE KEY-----"),
			ok:   false,
		},
		{
			name: "OpenSSH armor, corrupt body",
			key:  []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"),
			ok:   false,
		},
		{
			name: "truncated header",
			key:  opensshMagic[:len(opensshMagic)-1],
			ok:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rounds, ok := opensshBcryptRounds(tt.key)
			if ok != tt.ok {
				t.Errorf("opensshBcryptRounds() ok = %v, want %v", ok, tt.ok)
				return
			}
			if ok && rounds != tt.rounds {
				t.Errorf("opensshBcryptRounds() rounds = %d, want %d", rounds, tt.rounds)
			}
		})
	}
}

func BenchmarkParseWrongPassword(b *testing.B) {
	for n := 0; n < b.N; n++ {
		ssh.ParseRawPrivateKeyWithPassphrase(testEncryptedKey, testEncryptedKeyIncorrectPassword)
	}
}

func BenchmarkParseRightPassword(b *testing.B) {
	for n := 0; n < b.N; n++ {
		ssh.ParseRawPrivateKeyWithPassphrase(testEncryptedKey, testEncryptedKeyCorrectPassword)
	}
}

func BenchmarkCracker(b *testing.B) {
	for n := 0; n < b.N; n++ {
		Crack(context.Background(), testEncryptedKey)
	}
}
