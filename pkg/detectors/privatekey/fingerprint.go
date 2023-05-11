package privatekey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

var (
	ErrNotSupported = errors.New("key type not supported")
	ErrEncryptedKey = errors.New("key is encrypted")
)

func FingerprintPEMKey(in []byte) (string, error) {
	parsedKey, err := ssh.ParseRawPrivateKey(in)
	if err != nil && strings.Contains(err.Error(), "private key is passphrase protected") {
		parsedKey, err = crack(in)
		if err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}

	var pubKey interface{}
	switch privateKey := parsedKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &privateKey.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &privateKey.PublicKey
	case *ed25519.PrivateKey:
		pubKey = privateKey.Public()
	// No fingerprinting support for DSA
	// case *dsa.PrivateKey:
	// 	pubKey = privateKey.PublicKey
	default:
		return "", ErrNotSupported
	}

	publickeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	publicKeyFingerprint := sha1.Sum(publickeyBytes)
	publicKeyFingerprintInHex := hex.EncodeToString(publicKeyFingerprint[:])
	return publicKeyFingerprintInHex, nil
}
