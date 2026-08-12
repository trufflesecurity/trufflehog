package vaultroottoken

import (
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

var (
	// Vault root tokens should be detected in explicit root-token context to avoid
	// overlapping with generic service-token detectors.
	rootTokenPat = regexp.MustCompile(`(?i)(?:initial\s+root\s+token|root[_\s-]*token|VAULT_ROOT_TOKEN)\s*[:=]\s*["']?(hvs\.[A-Za-z0-9_-]{20,}|s\.[A-Za-z0-9_-]{24,})["']?`)
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
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_VaultRootToken,
			Raw:          []byte(token),
		}

		if verify {
			// Root tokens should never be live-verified against Vault APIs.
			r.Verified = verifyVaultRootTokenFormat(token)
		}

		results = append(results, r)
	}

	return results, nil
}

func verifyVaultRootTokenFormat(token string) bool {
	if len(token) < 26 {
		return false
	}
	return (len(token) > 4 && token[:4] == "hvs.") || (len(token) > 2 && token[:2] == "s.")
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_VaultRootToken
}

func (s Scanner) Description() string {
	return "HashiCorp Vault root tokens grant unrestricted administrative access to Vault. Exposed root tokens should be rotated immediately."
}
