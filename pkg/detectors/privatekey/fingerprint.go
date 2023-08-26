package privatekey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/ssh"
)

var (
	ErrNotSupported = errors.New("key type not supported")
	ErrEncryptedKey = errors.New("key is encrypted")

	protectedKeyErrMsg = []byte("private key is passphrase protected")
)

func FingerprintPEMKey(in []byte) ([]byte, error) {
	parsedKey, err := ssh.ParseRawPrivateKey(in)
	if err != nil && bytes.Contains([]byte(err.Error()), protectedKeyErrMsg) {
		parsedKey, err = crack(in)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	var pubKey interface{}
	switch privateKey := parsedKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &privateKey.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &privateKey.PublicKey
	case *ed25519.PrivateKey:
		pubKey = privateKey.Public()
	default:
		return nil, ErrNotSupported
	}

	publickeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	publicKeyFingerprint := sha1.Sum(publickeyBytes)
	publicKeyFingerprintInHex := hex.EncodeToString(publicKeyFingerprint[:])
	return []byte(publicKeyFingerprintInHex), nil
}
