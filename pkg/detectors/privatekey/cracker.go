package privatekey

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"errors"

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

func crack(in []byte) (any, string, error) {
	for _, passphrase := range passphrases {
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
