package base64privatekey

import (
	"context"
	"encoding/base64"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	// Match base64 encoded strings that might contain private keys
	// Look for base64 strings that decode to contain "BEGIN.*PRIVATE KEY"
	base64Pat = regexp.MustCompile(`[A-Za-z0-9+/]{100,}={0,2}`)

	// After decoding, check for private key markers
	privateKeyMarkers = []string{
		"BEGIN RSA PRIVATE KEY",
		"BEGIN DSA PRIVATE KEY",
		"BEGIN EC PRIVATE KEY",
		"BEGIN PRIVATE KEY",
		"BEGIN ENCRYPTED PRIVATE KEY",
		"BEGIN OPENSSH PRIVATE KEY",
	}
)

func (s Scanner) Keywords() []string {
	return []string{"private", "key", "rsa", "BEGIN"}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Base64PrivateKey
}

func (s Scanner) Description() string {
	return "Base64-encoded private keys found in code can expose cryptographic credentials. These keys should be stored securely and never committed to version control."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})

	// Find potential base64 strings
	for _, match := range base64Pat.FindAllString(dataStr, -1) {
		match = strings.TrimSpace(match)

		// Try to decode
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err != nil {
			// Try URL encoding
			decoded, err = base64.URLEncoding.DecodeString(match)
			if err != nil {
				continue
			}
		}

		decodedStr := string(decoded)

		// Check if decoded content contains private key markers
		isPrivateKey := false
		for _, marker := range privateKeyMarkers {
			if strings.Contains(decodedStr, marker) {
				isPrivateKey = true
				break
			}
		}

		if isPrivateKey {
			uniqueMatches[match] = struct{}{}
		}
	}

	for encodedKey := range uniqueMatches {
		r := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(encodedKey),
			SecretParts: map[string]string{
				"base64_key": encodedKey,
			},
			ExtraData: map[string]string{
				"warning": "Base64-encoded private key detected. Decode to identify key type.",
			},
		}

		// Private keys cannot be verified without knowing the corresponding public key or service
		// So we just flag them as found
		r.Verified = false

		results = append(results, r)
	}

	return results, nil
}

func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	return detectors.IsKnownFalsePositive(string(result.Raw), detectors.DefaultFalsePositives, true)
}
