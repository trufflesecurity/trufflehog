package tableau

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)

func (Scanner) CloudEndpoint() string { return "" }

var (
	defaultClient = common.SaneHttpClient()

	// Pattern for Personal Access Token Names - Updated to handle JSON
	tokenNamePat       = regexp.MustCompile(`(?i)\b(?:(?:tableau)[_-]?)?(?:token[_-]?name|pat[_-]?name|personal[_-]?access[_-]?token[_-]?name|access[_-]?token[_-]?name|pod[_-]?name|personal[_-]?token[_-]?name|api[_-]?token[_-]?name)[_\s]*[:=]\s*["']?([a-zA-Z0-9_-]{3,50})["']?`)
	quotedTokenNamePat = regexp.MustCompile(`(?i)["'](?:tableau[_-]?)?(?:token[_-]?name|pat[_-]?name|personal[_-]?access[_-]?token[_-]?name|access[_-]?token[_-]?name|pod[_-]?name|personal[_-]?token[_-]?name|api[_-]?token[_-]?name)["']\s*:\s*["']([a-zA-Z0-9_-]{3,50})["']`)

	// Pattern for Personal Access Token Secrets - Updated to handle JSON
	tokenSecretPat = regexp.MustCompile(`\b([A-Za-z0-9+/]{22}==:[A-Za-z0-9]{32})\b`)

	// Pattern for Tableau Server URLs
	tableauURLPat = regexp.MustCompile(`(?i)(?:https?://)?([a-zA-Z0-9\-]+\.online\.tableau\.com)(?:/.*)?`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{
		"personal_access_token",
		"personalAccessToken",
		"pat",
		"tableau",
	}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Tableau Personal Access Token credentials in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Extract token names, secrets, and URLs separately
	tokenNames := extractTokenNames(dataStr)
	tokenSecrets := extractTokenSecrets(dataStr)
	foundURLs := extractTableauURLs(dataStr)

	// If no names or secrets found, return empty results
	if len(tokenNames) == 0 || len(tokenSecrets) == 0 {
		return results, nil
	}

	// Get all endpoints to test
	var endpointsToTest []string

	if len(foundURLs) > 0 {
		// Use found URLs only
		for url := range foundURLs {
			endpointsToTest = append(endpointsToTest, url)
		}
	} else {
		// Check if the input contains any tableau.com reference (even invalid ones)
		// If it does, don't use default endpoints - it means they provided a URL but it was invalid
		if strings.Contains(strings.ToLower(dataStr), "online.tableau.com") {
			// Invalid tableau URL found, don't use defaults
			return results, nil
		}

		// No URLs found at all, use configured endpoints
		endpointsToTest = append(endpointsToTest, s.Endpoints("")...)
	}

	// Prepare results slice with estimated capacity
	results = make([]detectors.Result, 0, len(tokenNames)*len(tokenSecrets)*len(endpointsToTest))

	// Process each combination of token name, token secret, and endpoint
	for tokenName := range tokenNames {
		for tokenSecret := range tokenSecrets {
			for _, endpoint := range endpointsToTest {
				result := detectors.Result{
					DetectorType: detectorspb.DetectorType_Tableau,
					Raw:          []byte(tokenName),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", tokenName, tokenSecret, endpoint)),
					ExtraData: map[string]string{
						"credential_type": "personal_access_token",
					},
				}

				if verify {
					client := s.getClient()
					isVerified, extraData, verificationErr := verifyTableauPAT(ctx, client, tokenName, tokenSecret, endpoint)
					result.Verified = isVerified

					// Merge verification extra data
					maps.Copy(result.ExtraData, extraData)

					result.SetVerificationError(verificationErr, fmt.Sprintf("%s:%s@%s", tokenName, tokenSecret, endpoint))
				}

				results = append(results, result)
			}
		}
	}

	return results, nil
}

// extractTokenNames finds all potential token names in the data
func extractTokenNames(data string) map[string]struct{} {
	names := make(map[string]struct{})

	// Find matches using the token name pattern
	for _, match := range tokenNamePat.FindAllStringSubmatch(data, -1) {
		if len(match) >= 2 {
			name := strings.TrimSpace(match[1])
			if name != "" && len(name) >= 3 { // Minimum reasonable token name length
				names[name] = struct{}{}
			}
		}
	}

	// Find matches using the quoted token name pattern
	for _, match := range quotedTokenNamePat.FindAllStringSubmatch(data, -1) {
		if len(match) >= 2 {
			name := strings.TrimSpace(match[1])
			if name != "" && len(name) >= 3 { // Minimum reasonable token name length
				names[name] = struct{}{}
			}
		}
	}
	return names
}

// extractTokenSecrets finds all potential token secrets in the data
func extractTokenSecrets(data string) map[string]struct{} {
	secrets := make(map[string]struct{})

	// Find matches using the general secret pattern only
	for _, match := range tokenSecretPat.FindAllStringSubmatch(data, -1) {
		if len(match) >= 2 {
			secret := strings.TrimSpace(match[1])
			if isValidSecretFormat(secret) {
				secrets[secret] = struct{}{}
			}
		}
	}

	return secrets
}

// extractTableauURLs finds all potential Tableau server URLs in the data
func extractTableauURLs(data string) map[string]struct{} {
	urls := make(map[string]struct{})

	// Find matches using the Tableau URL pattern
	for _, match := range tableauURLPat.FindAllStringSubmatch(data, -1) {
		if len(match) >= 2 {
			url := strings.TrimSpace(match[1]) // This now captures the full URL including .online.tableau.com
			if url != "" {
				urls[url] = struct{}{}
			}
		}
	}

	return urls
}

// isValidSecretFormat validates that the secret matches expected Tableau PAT format
func isValidSecretFormat(secret string) bool {
	if len(secret) < 20 { // Minimum reasonable length
		return false
	}

	parts := strings.Split(secret, ":")
	if len(parts) != 2 {
		return false
	}

	// First part should look like base64 (may end with =)
	base64Part := parts[0]
	if len(base64Part) < 16 {
		return false
	}

	// Second part should be alphanumeric
	tokenPart := parts[1]
	if len(tokenPart) < 20 {
		return false
	}

	// Basic pattern validation
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	tokenPattern := regexp.MustCompile(`^[A-Za-z0-9]+$`)

	return base64Pattern.MatchString(base64Part) && tokenPattern.MatchString(tokenPart)
}

// TableauAuthRequest represents the authentication request structure
type TableauAuthRequest struct {
	Credentials TableauCredentials `json:"credentials"`
}

type TableauCredentials struct {
	PersonalAccessTokenName   string      `json:"personalAccessTokenName"`
	PersonalAccessTokenSecret string      `json:"personalAccessTokenSecret"`
	Site                      interface{} `json:"site"`
}

// TableauAuthResponse represents the authentication response structure
type TableauAuthResponse struct {
	Credentials struct {
		Site struct {
			ID         string `json:"id"`
			ContentURL string `json:"contentUrl"`
		} `json:"site"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Token string `json:"token"`
	} `json:"credentials"`
}

// verifyTableauPAT verifies a Tableau Personal Access Token by attempting authentication
func verifyTableauPAT(ctx context.Context, client *http.Client, tokenName, tokenSecret, endpoint string) (bool, map[string]string, error) {
	// Build the verification URL
	verifyURL := fmt.Sprintf("https://%s/api/3.26/auth/signin", endpoint)

	// Rest of your verification logic...
	authReq := TableauAuthRequest{
		Credentials: TableauCredentials{
			PersonalAccessTokenName:   tokenName,
			PersonalAccessTokenSecret: tokenSecret,
			Site:                      map[string]interface{}{},
		},
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(authReq)
	if err != nil {
		return false, nil, fmt.Errorf("failed to marshal auth request: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return false, nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("request failed: %v", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// Read the response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Prepare metadata
	extraData := map[string]string{
		"verification_endpoint": verifyURL,
		"http_status":           fmt.Sprintf("%d", resp.StatusCode),
		"verification_method":   "tableau_pat_auth",
		"tableau_endpoint":      endpoint,
	}

	// Status code handling...
	switch resp.StatusCode {
	case http.StatusOK:
		var authResp TableauAuthResponse
		if err := json.Unmarshal(bodyBytes, &authResp); err == nil {
			if token := authResp.Credentials.Token; token != "" {
				extraData["auth_token_received"] = "true"
				extraData["site_id"] = authResp.Credentials.Site.ID
				extraData["user_id"] = authResp.Credentials.User.ID
				extraData["verification_status"] = "valid"
				return true, extraData, nil
			}
		}
		// Fallback success on 200
		extraData["verification_status"] = "valid"
		return true, extraData, nil

	case http.StatusUnauthorized:
		extraData["verification_status"] = "invalid"
		return false, extraData, nil

	case http.StatusBadRequest:
		extraData["verification_status"] = "invalid_format"
		return false, extraData, nil

	case http.StatusForbidden:
		extraData["verification_status"] = "insufficient_permissions"
		return false, extraData, nil

	default:
		extraData["verification_status"] = "error"
		return false, extraData, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Tableau
}

func (s Scanner) Description() string {
	return "Tableau is a data visualization and business intelligence platform. Personal Access Tokens (PATs) provide programmatic access to Tableau Server/Online APIs and can be used to authenticate applications and automate workflows."
}
