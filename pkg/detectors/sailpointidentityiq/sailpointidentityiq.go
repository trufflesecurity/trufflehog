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

var (
	_ detectors.Detector                   = (*Scanner)(nil)
	_ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)
	_ detectors.MaxSecretSizeProvider      = (*Scanner)(nil)
)

// RE2 caps repetitions at 1,000, so five adjacent groups enforce 5,000.
var keyPat = regexp.MustCompile("\\b(1:ACP:[A-Za-z0-9+/=]{43,1000}[A-Za-z0-9+/=]{0,1000}[A-Za-z0-9+/=]{0,1000}[A-Za-z0-9+/=]{0,1000}[A-Za-z0-9+/=]{0,1000})(?:[\\t\\r\\n \\\"']|$)")

// SailPoint IdentityIQ's globally shipped AES key for alias 1.
// Decryption behavior ported from https://github.com/covertchannelblog/iiq_decrypt.
var defaultKey = []byte{0x8c, 0x34, 0xaf, 0x4f, 0xab, 0xa6, 0x15, 0xbe, 0x29, 0xb2, 0x98, 0x9b, 0xa4, 0xf0, 0x08, 0x55}

func (Scanner) Keywords() []string { return []string{"1:ACP:"} }

func (Scanner) MaxSecretSize() int64 { return 5006 }

func (Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_SailPointIdentityIQ
}

func (Scanner) Description() string {
	return "SailPoint IdentityIQ ACP secrets contain AES-encrypted configuration passwords."
}

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	for _, groups := range keyPat.FindAllStringSubmatch(string(data), -1) {
		plaintext, secret, err := decryptMatch(groups[1])
		if err != nil {
			continue
		}

		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_SailPointIdentityIQ,
			Raw:          plaintext,
			SecretParts:  map[string]string{"key": string(plaintext)},
		}
		result.SetPrimarySecretValue(secret)
		results = append(results, result)
	}
	return results, nil
}

// IsFalsePositive bypasses the generic plaintext wordlist because a candidate
// has already passed IdentityIQ-specific decryption and padding validation.
func (Scanner) IsFalsePositive(_ detectors.Result) (bool, string) { return false, "" }

// decryptMatch trims Base64-looking text after an unpadded secret, preferring
// the longest prefix that decrypts successfully.
func decryptMatch(match string) ([]byte, string, error) {
	for end := len(match); end >= len("1:ACP:")+43; end-- {
		if (end-len("1:ACP:"))%4 != 0 {
			continue
		}
		secret := match[:end]
		plaintext, err := decrypt(secret)
		if err == nil {
			return plaintext, secret, nil
		}
	}
	return nil, "", errors.New("invalid ACP secret")
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
