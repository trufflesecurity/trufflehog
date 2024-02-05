//go:build detectors
// +build detectors

package privatekey

import (
	_ "embed"
	"testing"

	"golang.org/x/crypto/ssh"
)

var (
	testEncryptedKeyCorrectPassword   = []byte("123456")
	testEncryptedKeyIncorrectPassword = []byte("incorrect")
	testEncryptedKey                  = []byte(normalize(`-----BEGIN OPENSSH PRIVATE KEY-----
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
Hx7UPVlTK8dyvk1Z+Yw0nrfNClI=
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
			_, passphrase, err := crack(tt.in)
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
		crack(testEncryptedKey)
	}
}
