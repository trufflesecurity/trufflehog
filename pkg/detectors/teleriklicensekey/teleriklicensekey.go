package teleriklicensekey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

// Ensure the Scanner satisfies expected interfaces at compile time.
var _ interface {
	detectors.Detector
	detectors.MaxSecretSizeProvider
} = (*Scanner)(nil)

const maxSecretSize = 4096

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)\b`)
)

// The default max secret size value for this detector must be overridden or JWTs with lots of claims will get missed.
func (Scanner) MaxSecretSize() int64 {
	return maxSecretSize
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"eyJ"}
}

// FromData will find and optionally verify Teleriklicensekey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		// Always check if this is a Telerik license key (local validation, not remote)
		isTelerik, _ := isTelerikLicenseKey(match)
		if !isTelerik {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_TelerikLicenseKey,
			Raw:          []byte(match),
		}

		results = append(results, s1)
	}

	return
}

func isTelerikLicenseKey(token string) (bool, error) {
	// Decode JWT header to verify typ claim
	headerClaims, err := decodeJWT(token)
	if err != nil {
		return false, fmt.Errorf("failed to decode JWT: %w", err)
	}

	// Get the token type from header - should be "Telerik License Key"
	tokenType, ok := headerClaims["typ"].(string)
	if ok && tokenType == "Telerik License Key" {
		return true, nil
	}

	return false, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_TelerikLicenseKey
}

func (s Scanner) Description() string {
	return "Telerik and Kendo license keys are for product license validation that verify the developer compiling an application has active license(s) for the version of the Telerik/Kendo product being used in the project."
}

// This function decodes the JWT header so we can verify the typ=Telerik License Key. No remote API call needed!
func decodeJWT(token string) (map[string]interface{}, error) {
	// Split the JWT into its three parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the header (first part)
	header := parts[0]

	// Add padding if necessary for base64 decoding
	if padding := len(header) % 4; padding != 0 {
		header += strings.Repeat("=", 4-padding)
	}

	// Decode from base64
	decoded, err := base64.URLEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 header: %w", err)
	}

	// Parse JSON
	var headerClaims map[string]interface{}
	if err := json.Unmarshal(decoded, &headerClaims); err != nil {
		return nil, fmt.Errorf("failed to parse JSON header: %w", err)
	}

	return headerClaims, nil
}
