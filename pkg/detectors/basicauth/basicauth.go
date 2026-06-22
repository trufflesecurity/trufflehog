package basicauth

import (
	"context"
	"encoding/base64"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	// Pattern matches Authorization: Basic <base64> or similar variations
	// The base64 part should contain at least one colon when decoded (username:password format)
	keyPat = regexp.MustCompile(`(?i)(?:authorization|auth)[\s:=]+basic[\s]+([A-Za-z0-9+/]{20,}={0,2})`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"authorization", "basic", "auth"}
}

// FromData will find and optionally verify BasicAuth secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		// Decode base64 to verify it contains username:password format
		decoded, err := base64.StdEncoding.DecodeString(resMatch)
		if err != nil {
			// Try URL encoding as fallback
			decoded, err = base64.URLEncoding.DecodeString(resMatch)
			if err != nil {
				continue
			}
		}

		decodedStr := string(decoded)

		// Basic auth must contain at least one colon separating username and password
		if !strings.Contains(decodedStr, ":") {
			continue
		}

		// Split to get username and password
		parts := strings.SplitN(decodedStr, ":", 2)
		if len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) == 0 {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_BasicAuth,
			Raw:          []byte(resMatch),
			RawV2:        []byte(decodedStr),
			SecretParts: map[string]string{
				"username": parts[0],
				"password": parts[1],
				"encoded":  resMatch,
			},
		}

		// Basic auth tokens cannot be verified without knowing the target URL/endpoint
		// So we mark them as unverified by default
		s1.Verified = false

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_BasicAuth
}

func (s Scanner) Description() string {
	return "HTTP Basic Authentication is a simple authentication scheme built into the HTTP protocol. Basic Auth credentials consist of a username and password encoded in base64 format."
}
