package privatekey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

var (
	ErrNotSupported = errors.New("key type not supported")
	ErrEncryptedKey = errors.New("key is encrypted")
)

func FingerprintPEMKey(parsedKey any) (string, error) {
	var pubKey any
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

	return fingerprintPublicKey(pubKey)
}

func fingerprintPublicKey(pubKey any) (string, error) {
	publickeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	publicKeyFingerprint := sha1.Sum(publickeyBytes)
	publicKeyFingerprintInHex := hex.EncodeToString(publicKeyFingerprint[:])
	return publicKeyFingerprintInHex, nil
}

func fingerprintSSHPublicKey(pubKey ssh.PublicKey) string {
	publicKeyFingerprint := sha256.Sum256(pubKey.Marshal())
	return fmt.Sprintf("SHA256:%s", base64.RawStdEncoding.EncodeToString(publicKeyFingerprint[:]))
}
