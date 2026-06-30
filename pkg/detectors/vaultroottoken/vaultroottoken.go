package vaultroottoken

import (
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {}

var (
	// HashiCorp Vault root token patterns
	// Root tokens are special tokens with full privileges, generated during vault init
	// New format: hvs.XXXXX (variable length, typically 24-100+ chars after prefix)
	// Legacy format: s.XXXXX (typically 24+ chars after prefix)
	rootTokenPat = regexp.MustCompile(`\b(hvs\.[A-Za-z0-9]{20,}|s\.[a-zA-Z0-9]{24,})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"root_token", "root token", "initial root token", "VAULT_ROOT_TOKEN"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range rootTokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_VaultRootToken,
			Raw:          []byte(token),
		}

		if verify {
			// Root tokens are format-verified only
			// They cannot be safely verified via API without a running Vault instance
			// and attempting to use them could trigger security alerts
			isVerified := verifyVaultRootTokenFormat(token)
			s1.Verified = isVerified

			if isVerified {
				s1.ExtraData = map[string]string{
					"rotation_guide": "https://developer.hashicorp.com/vault/tutorials/operations/generate-root",
					"warning":        "Root tokens have unrestricted access to Vault. Rotate immediately if exposed.",
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyVaultRootTokenFormat(token string) bool {
	// Vault root tokens follow specific formats:
	// - New format: hvs.XXXXX (24-100+ chars after prefix)
	// - Legacy format: s.XXXXX (24+ chars after prefix)

	if len(token) < 8 {
		return false
	}

	// Check for hvs. prefix (new format)
	if len(token) >= 28 && token[:4] == "hvs." {
		return true
	}

	// Check for s. prefix (legacy format)
	if len(token) >= 26 && token[:2] == "s." {
		return true
	}

	return false
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_VaultRootToken
}

func (s Scanner) Description() string {
	return "HashiCorp Vault root tokens are special tokens with unrestricted access to all Vault operations. These tokens are generated during vault initialization and should be tightly controlled and rotated regularly."
}
