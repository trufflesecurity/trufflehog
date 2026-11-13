package privatekey

import (
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

//go:embed "list.txt"
var rawCrackList []byte
var passphrases [][]byte

func init() {
	passphrases = bytes.Split(rawCrackList, []byte("\n"))
}

var (
	ErrUncrackable = errors.New("unable to crack encryption")
	// ErrKDFTooExpensive is returned without attempting any passphrase when a
	// key's KDF is more expensive than the crack budget allows.
	ErrKDFTooExpensive = errors.New("key KDF is too expensive to crack")
)

// maxCrackRounds caps the bcrypt KDF round count this detector will attempt
// to crack. The round count is chosen by whoever created the key and the KDF
// cost is linear in rounds; OpenSSH's default is 16. A key hardened beyond
// this cap is reported as an unverified finding instead of spending the
// detector's whole time budget attempting to crack it. x/crypto refuses round
// counts above 2048 on its own, so this lower cap is what keeps
// hardened-but-legal keys from burning the timeout window.
const maxCrackRounds = 256

func Crack(ctx context.Context, in []byte) (any, string, error) {
	if rounds, ok := opensshBcryptRounds(in); ok && rounds > maxCrackRounds {
		return nil, "", fmt.Errorf("%w: %d rounds exceeds cap of %d", ErrKDFTooExpensive, rounds, maxCrackRounds)
	}
	for i, passphrase := range passphrases {
		// A wrong passphrase costs a full KDF run whose cost is set by the
		// key's author, so stop between attempts once the caller's context is
		// done. The in-flight attempt cannot be interrupted:
		// ssh.ParseRawPrivateKeyWithPassphrase takes no context.
		if err := ctx.Err(); err != nil {
			return nil, "", fmt.Errorf("stopped cracking after %d of %d passphrase attempts: %w", i, len(passphrases), err)
		}
		parsed, err := ssh.ParseRawPrivateKeyWithPassphrase(in, passphrase)
		if err != nil {
			if errors.Is(err, x509.IncorrectPasswordError) {
				continue
			} else {
				return nil, "", err
			}
		}
		return parsed, string(passphrase), nil
	}
	return nil, "", ErrUncrackable
}
