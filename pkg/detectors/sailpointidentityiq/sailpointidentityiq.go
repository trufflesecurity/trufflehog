package sailpointidentityiq

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"unicode/utf8"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var keyPat = regexp.MustCompile(`\b(1:ACP:[A-Za-z0-9+/]{43,}={0,2})`)

// SailPoint IdentityIQ's globally shipped AES key for alias 1.
// Decryption behavior ported from https://github.com/covertchannelblog/iiq_decrypt.
var defaultKey = []byte{0x8c, 0x34, 0xaf, 0x4f, 0xab, 0xa6, 0x15, 0xbe, 0x29, 0xb2, 0x98, 0x9b, 0xa4, 0xf0, 0x08, 0x55}

func (Scanner) Keywords() []string { return []string{"1:ACP:"} }

func (Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_SailPointIdentityIQ
}

func (Scanner) Description() string {
	return "SailPoint IdentityIQ ACP secrets contain AES-encrypted configuration passwords."
}

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	for _, groups := range keyPat.FindAllStringSubmatch(string(data), -1) {
		plaintext, err := decrypt(groups[1])
		if err != nil {
			continue
		}

		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_SailPointIdentityIQ,
			Raw:          plaintext,
			SecretParts:  map[string]string{"key": string(plaintext)},
		}
		result.SetPrimarySecretValue(groups[1])
		results = append(results, result)
	}
	return results, nil
}

func decrypt(secret string) ([]byte, error) {
	encoded := secret[len("1:ACP:"):]
	encrypted, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(encrypted) <= aes.BlockSize || len(encrypted)%aes.BlockSize != 0 {
		return nil, errors.New("invalid ACP ciphertext")
	}

	block, err := aes.NewCipher(defaultKey)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(encrypted)-aes.BlockSize)
	cipher.NewCBCDecrypter(block, encrypted[:aes.BlockSize]).CryptBlocks(plaintext, encrypted[aes.BlockSize:])

	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(plaintext) {
		return nil, errors.New("invalid ACP padding")
	}
	for _, b := range plaintext[len(plaintext)-padding:] {
		if int(b) != padding {
			return nil, errors.New("invalid ACP padding")
		}
	}
	plaintext = plaintext[:len(plaintext)-padding]
	if !utf8.Valid(plaintext) {
		return nil, errors.New("invalid ACP plaintext")
	}
	return plaintext, nil
}
