package streamio

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

var (
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	// Stream.io requires App ID, API Key, and API Secret
	// App ID format: numeric, typically 5-10 digits
	// API Key format: alphanumeric, typically 8-20 characters
	// API Secret format: alphanumeric, typically 40-80 characters
	appIdPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"stream", "app.?id", "getstream"}) + `\b([0-9]{5,10})\b`)
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"stream", "api.?key", "getstream"}) + `\b([a-z0-9]{8,20})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"stream", "api.?secret", "getstream"}) + `\b([a-z0-9]{40,80})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"stream", "getstream", "stream.io"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Stream.io secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueAppIds := make(map[string]struct{})
	uniqueKeys := make(map[string]struct{})
	uniqueSecrets := make(map[string]struct{})

	for _, match := range appIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAppIds[match[1]] = struct{}{}
	}

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[match[1]] = struct{}{}
	}

	for _, match := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecrets[match[1]] = struct{}{}
	}

	// If no app IDs found, add empty string so we can still detect key+secret pairs
	if len(uniqueAppIds) == 0 {
		uniqueAppIds[""] = struct{}{}
	}

	for appId := range uniqueAppIds {
		for apiKey := range uniqueKeys {
			for apiSecret := range uniqueSecrets {
				secretParts := map[string]string{
					"api_key":    apiKey,
					"api_secret": apiSecret,
				}
				if appId != "" {
					secretParts["app_id"] = appId
				}

				s1 := detectors.Result{
					DetectorType: detector_typepb.DetectorType_StreamIO,
					Raw:          []byte(apiKey),
					RawV2:        []byte(appId + apiKey + apiSecret),
					SecretParts:  secretParts,
				}

				if verify {
					isVerified, verificationErr := verifyStreamIO(ctx, s.getClient(), appId, apiKey, apiSecret)
					s1.Verified = isVerified
					s1.SetVerificationError(verificationErr, apiSecret)
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func verifyStreamIO(ctx context.Context, client *http.Client, appId, apiKey, apiSecret string) (bool, error) {
	// GetStream.io requires JWT tokens for authentication
	// Generate a token with feed access claims
	token, err := generateStreamToken(apiSecret)
	if err != nil {
		return false, fmt.Errorf("failed to generate token: %w", err)
	}

	// Try different regional endpoints
	locations := []string{
		"us-east",
		"eu-west",
		"singapore",
		"sydney",
		"tokyo",
	}

	var lastErr error
	var lastStatus int

	for _, location := range locations {
		// Try accessing a feed endpoint to verify credentials
		// We use a generic feed path - the feed may not exist but auth will be checked first
		url := fmt.Sprintf("https://%s-api.stream-io-api.com/api/v1.0/feed/flat/verify/?api_key=%s",
			location, apiKey)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err
			continue
		}

		// Set authorization header with JWT token
		req.Header.Set("Authorization", token)
		req.Header.Set("Stream-Auth-Type", "jwt")

		res, err := client.Do(req)
		if err != nil {
			// DNS or network error, try next location
			lastErr = err
			continue
		}

		bodyBytes, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		lastStatus = res.StatusCode

		switch res.StatusCode {
		case http.StatusOK:
			// Valid credentials and feed exists
			return true, nil
		case http.StatusBadRequest:
			// Feed doesn't exist but auth succeeded (400 = authenticated but bad request)
			// This confirms valid credentials
			return true, nil
		case http.StatusUnauthorized, http.StatusForbidden:
			// Invalid credentials
			// Check if all regions give same error - if yes, credentials are definitely invalid
			bodyStr := string(bodyBytes)
			lastErr = fmt.Errorf("auth failed (status %d): %s", res.StatusCode, bodyStr)
			continue
		case http.StatusNotFound:
			// Endpoint not found at this location, try next
			lastErr = fmt.Errorf("endpoint not found at %s", location)
			continue
		default:
			// Other status codes (might indicate successful auth but other issues)
			lastErr = fmt.Errorf("status %d from %s: %s", res.StatusCode, location, string(bodyBytes))
			continue
		}
	}

	// If we consistently get 401/403 across all regions, credentials are invalid
	if lastStatus == http.StatusUnauthorized || lastStatus == http.StatusForbidden {
		return false, lastErr
	}

	// Otherwise, couldn't verify (network/config issues)
	if lastErr != nil {
		return false, lastErr
	}
	return false, fmt.Errorf("all locations failed")
}

// generateStreamToken creates a JWT token for Stream.io authentication
func generateStreamToken(apiSecret string) (string, error) {
	// Stream.io uses HS256 for signing
	// Include resource claims for feed access
	claims := jwt.MapClaims{
		"resource": "feed",
		"action":   "*",
		"feed_id":  "*",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(apiSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_StreamIO
}

func (s Scanner) Description() string {
	return "Stream (GetStream.io) is a scalable feed and chat API service. Stream API keys and secrets can be used to authenticate and access chat, activity feeds, and other Stream services."
}
