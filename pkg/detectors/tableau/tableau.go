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

	// Simplified token name pattern using PrefixRegex
	tokenNamePat = regexp.MustCompile(detectors.PrefixRegex([]string{"pat", "token", "name", "tableau"}) + `([a-zA-Z][a-zA-Z0-9_-]{2,50})`)

	// Pattern for Personal Access Token Secrets
	tokenSecretPat = regexp.MustCompile(`\b([A-Za-z0-9+/]{22}==:[A-Za-z0-9]{32})\b`)

	// Simplified Tableau Server URLs pattern
	tableauURLPat = regexp.MustCompile(`\b([a-zA-Z0-9\-]+\.online\.tableau\.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{
		"tableau",
		"online.tableau.com",
	}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

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

	// Use maps to deduplicate endpoints
	var uniqueEndpoints = make(map[string]struct{})

	// Add endpoints to the list
	for _, endpoint := range s.Endpoints(foundURLs...) {
		// Remove https:// prefix if present since we add it during verification
		endpoint = strings.TrimPrefix(endpoint, "https://")
		uniqueEndpoints[endpoint] = struct{}{}
	}

	// Process each combination of token name, token secret, and endpoint
	for _, tokenName := range tokenNames {
		for _, tokenSecret := range tokenSecrets {
			for endpoint := range uniqueEndpoints {
				result := detectors.Result{
					DetectorType: detectorspb.DetectorType_TableauPersonalAccessToken,
					Raw:          []byte(tokenName),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", tokenName, tokenSecret, endpoint)),
					ExtraData:    make(map[string]string),
				}

				if verify {
					client := s.getClient()
					isVerified, extraData, verificationErr := verifyTableauPAT(ctx, client, tokenName, tokenSecret, endpoint)
					result.Verified = isVerified
					maps.Copy(result.ExtraData, extraData)
					result.SetVerificationError(verificationErr, tokenName, tokenSecret, endpoint)
				}
				results = append(results, result)
			}
		}
	}

	return results, nil
}

// extractTokenNames finds all potential token names in the data
func extractTokenNames(data string) []string {
	var names []string
	// Create a map of false positive terms
	falsePositives := map[detectors.FalsePositive]struct{}{
		detectors.FalsePositive("com"): {},
	}

	for _, match := range tokenNamePat.FindAllStringSubmatch(data, -1) {
		if len(match) >= 2 {
			name := strings.TrimSpace(match[1])
			isFalsePositive, _ := detectors.IsKnownFalsePositive(name, falsePositives, false)
			if !isFalsePositive {
				names = append(names, name)
			}
		}
	}
	return names
}

// extractTokenSecrets finds all potential token secrets in the data
func extractTokenSecrets(data string) []string {
	var secrets []string
	for _, match := range tokenSecretPat.FindAllStringSubmatch(data, -1) {
		if len(match) >= 2 {
			secret := strings.TrimSpace(match[1])
			secrets = append(secrets, secret)
		}
	}
	return secrets
}

// extractTableauURLs finds all potential Tableau server URLs in the data
func extractTableauURLs(data string) []string {
	var urls []string

	for _, match := range tableauURLPat.FindAllStringSubmatch(data, -1) {
		if len(match) >= 2 {
			url := strings.TrimSpace(match[1])
			if url != "" {
				urls = append(urls, url)
			}
		}
	}

	return urls
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

	// Prepare metadata early - before any potential errors
	extraData := map[string]string{
		"verification_endpoint": verifyURL,
		"verification_method":   "tableau_pat_auth",
		"tableau_endpoint":      endpoint,
	}

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
		// Check if it's a DNS/network error
		if strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "dial tcp") ||
			strings.Contains(err.Error(), "connection refused") {
			extraData["network_error"] = "true"
			return false, extraData, nil // No error, just invalid endpoint
		}
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

	// Status code handling...
	switch resp.StatusCode {
	case http.StatusOK:
		var authResp TableauAuthResponse
		if err := json.Unmarshal(bodyBytes, &authResp); err != nil {
			return true, extraData, err
		}
		return true, extraData, nil

	case http.StatusUnauthorized, http.StatusBadRequest, http.StatusForbidden:
		return false, extraData, nil

	default:
		return false, extraData, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_TableauPersonalAccessToken
}

func (s Scanner) Description() string {
	return "Tableau is a data visualization and business intelligence platform. Personal Access Tokens (PATs) provide programmatic access to Tableau Server/Online APIs and can be used to authenticate applications and automate workflows."
}
