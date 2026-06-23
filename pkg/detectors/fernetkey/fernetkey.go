package fernetkey

import (
	"context"
	"encoding/base64"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Fernet keys are exactly 44 characters of URL-safe base64 (A-Za-z0-9_-) ending with =
	// They decode to exactly 32 bytes (signing key + encryption key)
	// Use a wider pattern since "fernet" keyword is already required for pre-filtering
	keyPat = regexp.MustCompile(`([A-Za-z0-9_-]{43}=)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"fernet", "FERNET"}
}

// FromData will find and optionally verify Fernetkey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_FernetKey,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
		}

		if verify {
			isVerified := verifyFernetKey(match)
			s1.Verified = isVerified
			if isVerified {
				s1.ExtraData = map[string]string{
					"rotation_guide": "https://cryptography.io/en/latest/fernet/",
				}
			}
		}

		results = append(results, s1)
	}

	return
}

// verifyFernetKey checks if the key is a valid Fernet key by:
// 1. Decoding from URL-safe base64
// 2. Verifying it's exactly 32 bytes (16 bytes signing key + 16 bytes encryption key)
func verifyFernetKey(key string) bool {
	// Attempt to decode the base64 string
	decoded, err := base64.URLEncoding.DecodeString(key)
	if err != nil {
		// Try with RawURLEncoding (without padding)
		decoded, err = base64.RawURLEncoding.DecodeString(key)
		if err != nil {
			return false
		}
	}

	// Fernet keys must be exactly 32 bytes
	return len(decoded) == 32
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_FernetKey
}

func (s Scanner) Description() string {
	return "Fernet keys are symmetric encryption keys used by Python's cryptography library. They provide authenticated encryption and are exactly 32 bytes encoded in URL-safe base64 format."
}
