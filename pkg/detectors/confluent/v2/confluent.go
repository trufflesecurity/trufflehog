package confluent

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"hash/crc32"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"confluent"}) + `\b([A-Z0-9]{16})\b`)
	// Match cflt prefix followed by 60 characters consisting of A-Z, a-z, 0-9, + or /
	//See https://docs.confluent.io/cloud/current/security/authenticate/workload-identities/service-accounts/api-keys/overview.html#api-secret-format
	secretPat = regexp.MustCompile(`\b(cflt[A-Za-z0-9+/]{60})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"cflt"}
}

func (s Scanner) Version() int { return 2 }

// FromData will find and optionally verify Confluent secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, match := range secretMatches {
			resSecret := strings.TrimSpace(match[1]) // Use index 1 for the captured group

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Confluent,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resSecret),
				ExtraData: map[string]string{
					"rotation_guide": "https://docs.confluent.io/cloud/current/security/authenticate/workload-identities/service-accounts/api-keys/best-practices-api-keys.html#rotate-api-keys-regularly",
					"version":        fmt.Sprintf("%d", s.Version()),
				},
			}

			if verify {
				s1.Verified = verifyConfluentSecret(resSecret)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

// verifyConfluentSecret verifies the Confluent secret by checking the CRC32 checksum
func verifyConfluentSecret(secret string) bool {
	if len(secret) != 64 { // cflt + 60 characters
		return false
	}

	if !strings.HasPrefix(secret, "cflt") {
		return false
	}

	// Extract the first 54 characters after 'cflt' prefix (58 total - 4 for cflt)
	payload := secret[4:58] // Characters 5-58 (54 characters)

	// Extract the last 6 characters as the checksum
	checksumEncoded := secret[58:64]

	// Decode the checksum from base64
	checksumBytes, err := b64.StdEncoding.DecodeString(checksumEncoded + "==") // Add padding if needed
	if err != nil {
		// Try without padding
		checksumBytes, err = b64.StdEncoding.DecodeString(checksumEncoded)
		if err != nil {
			return false
		}
	}

	if len(checksumBytes) < 4 {
		return false
	}

	// Calculate CRC32 checksum of the payload
	expectedChecksum := crc32.ChecksumIEEE([]byte(payload))

	// Convert received checksum bytes to uint32 (little endian to match the encoding)
	receivedChecksum := uint32(checksumBytes[3])<<24 | uint32(checksumBytes[2])<<16 |
		uint32(checksumBytes[1])<<8 | uint32(checksumBytes[0])

	return expectedChecksum == receivedChecksum
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Confluent
}

func (s Scanner) Description() string {
	return "Confluent provides a streaming platform based on Apache Kafka to help companies harness their data in real-time. Confluent Cloud API keys can be used to access and manage Confluent Cloud control plane APIs and resources."
}
