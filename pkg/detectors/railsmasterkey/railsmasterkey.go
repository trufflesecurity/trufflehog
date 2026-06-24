package railsmasterkey

import (
	"context"
	"encoding/hex"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Rails master keys are 32 or 64 hexadecimal characters
	// Rails 5.2+ uses 32 bytes (64 hex chars), but some configs use 16 bytes (32 hex chars)
	// Put longer pattern first to match 64-char keys before 32-char keys
	keyPat = regexp.MustCompile(`([0-9a-f]{64}|[0-9a-f]{32})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"master", "key", "rails", "secret", "credential"}
}

// FromData will find and optionally verify Railsmasterkey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_RailsMasterKey,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
		}

		if verify {
			isVerified := verifyRailsMasterKey(match)
			s1.Verified = isVerified
			if isVerified {
				s1.ExtraData = map[string]string{
					"rotation_guide": "https://guides.rubyonrails.org/security.html#custom-credentials",
				}
			}
		}

		results = append(results, s1)
	}

	return
}

// verifyRailsMasterKey checks if the key is a valid Rails master key by:
// 1. Verifying it's 32 or 64 hexadecimal characters
// 2. Decoding from hex to ensure it's valid hex encoding
func verifyRailsMasterKey(key string) bool {
	// Must be exactly 32 or 64 characters
	if len(key) != 32 && len(key) != 64 {
		return false
	}

	// Attempt to decode the hex string
	decoded, err := hex.DecodeString(key)
	if err != nil {
		return false
	}

	// Rails master keys are 16 bytes (32 hex) or 32 bytes (64 hex) when decoded
	return len(decoded) == 16 || len(decoded) == 32
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_RailsMasterKey
}

func (s Scanner) Description() string {
	return "Rails Master Keys are used by Ruby on Rails applications (version 5.2+) to encrypt credentials stored in config/credentials.yml.enc. These keys grant access to decrypt sensitive application secrets."
}
