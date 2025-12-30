package ranchertoken

import (
	"context"
	"fmt"
	"io"
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

	// Pattern to match Rancher/Cattle tokens with context
	// Token format: 54-64 lowercase alphanumeric characters
	// Handles various formats: env files, shell exports, YAML configs, Terraform HCL
	tokenPat = regexp.MustCompile(`(?i)(?:export\s+)?(?:CATTLE_TOKEN|RANCHER_TOKEN|CATTLE_BOOTSTRAP_PASSWORD|RANCHER_API_TOKEN|RANCHER_SECRET_KEY|token_key)[\w]*\s*[=:]\s*["']?([a-z0-9]{54,64})\b["']?`)

	// Pattern for YAML-style value on the next line (e.g., Kubernetes manifests)
	yamlValuePat = regexp.MustCompile(`(?i)(?:name:\s*(?:CATTLE_TOKEN|RANCHER_TOKEN|CATTLE_BOOTSTRAP_PASSWORD|RANCHER_API_TOKEN|RANCHER_SECRET_KEY))[\s\S]{0,50}value:\s*["']?([a-z0-9]{54,64})\b["']?`)

	// Pattern to extract server URL from common variable names
	serverPat = regexp.MustCompile(`(?i)(?:CATTLE_SERVER|RANCHER_URL|RANCHER_SERVER|rancher_api_url|api_url)\s*[=:]\s*["']?(https?://[^\s"']+)["']?`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"cattle_token", "rancher_token", "cattle_bootstrap", "rancher_api_token", "rancher_secret", "rancher2"}
}

// FromData will find and optionally verify Rancher tokens in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Find all token matches from both patterns
	tokenMatches := tokenPat.FindAllStringSubmatch(dataStr, -1)
	yamlMatches := yamlValuePat.FindAllStringSubmatch(dataStr, -1)

	// Combine all matches
	allMatches := append(tokenMatches, yamlMatches...)
	if len(allMatches) == 0 {
		return nil, nil
	}

	// Find server URLs from context
	var serverURLs []string
	serverMatches := serverPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range serverMatches {
		url := strings.TrimSpace(match[1])
		// Normalize URL - remove trailing slash
		url = strings.TrimRight(url, "/")
		serverURLs = append(serverURLs, url)
	}

	// Track unique tokens to avoid duplicates
	uniqueTokens := make(map[string]struct{})

	for _, match := range allMatches {
		token := strings.TrimSpace(match[1])

		// Skip if we've already processed this token
		if _, exists := uniqueTokens[token]; exists {
			continue
		}

		// Verify token is lowercase alphanumeric (the (?i) flag makes regex case-insensitive)
		if !isValidRancherToken(token) {
			continue
		}

		uniqueTokens[token] = struct{}{}

		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_RancherToken,
			Raw:          []byte(token),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			// Try to verify against any found server URLs
			verified := false
			var verificationErr error

			for _, serverURL := range serverURLs {
				verified, verificationErr = verifyRancherToken(ctx, client, serverURL, token)
				if verified {
					result.ExtraData = map[string]string{
						"server": serverURL,
					}
					break
				}
				// If we get a determinate failure (401), continue to try other URLs
				// If we get an indeterminate failure, we should report it
				if verificationErr != nil {
					break
				}
			}

			result.Verified = verified
			result.SetVerificationError(verificationErr, token)
		}

		results = append(results, result)
	}

	return results, nil
}

// verifyRancherToken verifies the token against the Rancher API.
// Endpoint: GET {server}/v3
// Header: Authorization: Bearer {token}
// Success: HTTP 200 with JSON containing "apiVersion"
// Failure: HTTP 401
func verifyRancherToken(ctx context.Context, client *http.Client, serverURL, token string) (bool, error) {
	url := fmt.Sprintf("%s/v3", serverURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		// Read response body to check for apiVersion
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}
		// Check if response contains apiVersion (basic check)
		if strings.Contains(string(body), "apiVersion") {
			return true, nil
		}
		// Response doesn't contain expected content
		return false, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// Determinately not verified
		return false, nil
	default:
		// Indeterminate failure
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_RancherToken
}

func (s Scanner) Description() string {
	return "Rancher is a Kubernetes management platform. Rancher/Cattle tokens can be used to access and manage Kubernetes clusters with full admin privileges."
}

// isValidRancherToken validates that the token is lowercase alphanumeric and 54-64 characters
func isValidRancherToken(token string) bool {
	if len(token) < 54 || len(token) > 64 {
		return false
	}
	for _, c := range token {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
