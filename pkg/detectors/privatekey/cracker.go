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
)

func Crack(ctx context.Context, in []byte) (any, string, error) {
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
