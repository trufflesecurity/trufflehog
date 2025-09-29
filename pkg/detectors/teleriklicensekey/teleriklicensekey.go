package teleriklicensekey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"teleriklicensekey"}) + `\b(eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+\/]*)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"teleriklicensekey", "eyJ"}
}

// FromData will find and optionally verify Teleriklicensekey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_TelerikLicenseKey,
			Raw:          []byte(match),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	// Decode JWT
	claims, err := decodeJWT(token)
	if err != nil {
		return false, nil, fmt.Errorf("failed to decode JWT: %w", err)
	}
	
	// Get the token type is "Telerik License Key"
	tokenType, ok := claims["typ"].(string)

	if ok && tokenType == "Telerik License Key" {
		// If the JWT's header "typ" claim is "Telerik License Key", consider it verified
		return true, nil, nil
	}

	// All other tokens are considered unverified
	return false, nil, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_TelerikLicenseKey
}

func (s Scanner) Description() string {
	return "Telerik and Kendo license keys are for product license validation that verify the developer compiling an application has active license(s) for the version of the Telerik/Kendo product being used in the project."
}

// This function decodes the JWT token so we can verify the typ=Telerik License Key. No remote API call needed!
func decodeJWT(token string) (map[string]interface{}, error) {
	// Split the JWT into its three parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (second part)
	payload := parts[1]
	
	// Add padding if necessary for base64 decoding
	if padding := len(payload) % 4; padding != 0 {
		payload += strings.Repeat("=", 4-padding)
	}

	// Decode from base64
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 payload: %w", err)
	}

	// Parse JSON
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JSON payload: %w", err)
	}

	return claims, nil
}
