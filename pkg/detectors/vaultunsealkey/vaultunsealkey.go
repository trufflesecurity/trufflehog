package vaultunsealkey

import (
	"context"
	"encoding/base64"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

var (
	// HashiCorp Vault unseal key pattern
	// Unseal keys are base64-encoded strings, typically 44 characters
	// Generated during vault operator init
	// Example: 4jYbl2CBIv6SpkKj6Hos9iD32k5RfGkLzlosrrq/JgOm
	unsealKeyPat = regexp.MustCompile(`\b([A-Za-z0-9+/]{44}={0,2})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"unseal", "unseal_key", "unseal key", "Unseal Key", "VAULT_UNSEAL_KEY"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range unsealKeyPat.FindAllStringSubmatch(dataStr, -1) {
		candidate := match[1]

		// Validate base64 format
		if isValidBase64(candidate) {
			uniqueMatches[candidate] = struct{}{}
		}
	}

	for key := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_VaultUnsealKey,
			Raw:          []byte(key),
		}

		if verify {
			// Vault unseal keys cannot be safely verified without:
			// 1. A sealed Vault instance
			// 2. Multiple keys (typically 3 of 5 required)
			// 3. Risk of unsealing production Vault
			// Therefore, we use format validation only
			isVerified := verifyVaultUnsealKeyFormat(key)
			s1.Verified = isVerified

			if isVerified {
				s1.ExtraData = map[string]string{
					"rotation_guide": "https://developer.hashicorp.com/vault/tutorials/operations/rekeying-and-rotating",
					"warning":        "Unseal keys provide access to decrypt Vault's encryption key. Rotate immediately if exposed.",
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyVaultUnsealKeyFormat(key string) bool {
	// Vault unseal keys are base64-encoded and exactly 44 characters
	// (32 bytes encoded as base64 = 44 chars including padding)
	if len(key) != 44 {
		return false
	}

	// Verify it's valid base64
	return isValidBase64(key)
}

func isValidBase64(s string) bool {
	// Attempt to decode as base64
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_VaultUnsealKey
}

func (s Scanner) Description() string {
	return "HashiCorp Vault unseal keys are used to reconstruct the master key and decrypt the encryption key. Typically 3-5 keys are generated during vault init, with a threshold (e.g., 3 of 5) required to unseal."
}
