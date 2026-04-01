package shopifyoauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	// Client secret has a distinctive prefix: shpss_ followed by 32 hex characters
	clientSecretPat = regexp.MustCompile(`\b(shpss_[a-fA-F0-9]{32})\b`)
	// Client ID is a generic 32-character alphanumeric string, requiring context
	clientIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"shopify", "client", "id"}) + `\b([a-zA-Z0-9]{32})\b`)
	// Domain pattern for Shopify stores
	domainPat = regexp.MustCompile(`\b([a-zA-Z0-9][-a-zA-Z0-9]*\.myshopify\.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"shpss_", "myshopify.com"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify ShopifyOAuth secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Extract all three components into unique maps
	uniqueSecrets := make(map[string]struct{})
	for _, match := range clientSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecrets[match[1]] = struct{}{}
	}

	uniqueClientIds := make(map[string]struct{})
	for _, match := range clientIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueClientIds[match[1]] = struct{}{}
	}

	uniqueDomains := make(map[string]struct{})
	for _, match := range domainPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueDomains[match[1]] = struct{}{}
	}

	// If we are missing any of the three components, we cannot form a valid credential.
	if len(uniqueSecrets) == 0 || len(uniqueClientIds) == 0 || len(uniqueDomains) == 0 {
		return nil, nil
	}

	for domain := range uniqueDomains {
		for clientId := range uniqueClientIds {
			for secret := range uniqueSecrets {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ShopifyOAuth,
					Raw:          []byte(secret),
					RawV2:        fmt.Appendf(nil, "%s:%s:%s", domain, clientId, secret),
				}

				if verify {
					isVerified, verificationErr := s.verifyMatch(ctx, s.getClient(), domain, clientId, secret)
					s1.Verified = isVerified
					s1.SetVerificationError(verificationErr, secret)
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

// verifyMatch attempts to validate Shopify OAuth credentials using the client_credentials grant.
func (s Scanner) verifyMatch(ctx context.Context, client *http.Client, domain, clientId, secret string) (bool, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientId)
	form.Set("client_secret", secret)

	authURL := url.URL{
		Scheme: "https",
		Host:   domain,
		Path:   "/admin/oauth/access_token",
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to perform request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusBadRequest, http.StatusNotFound:
		// 400 Bad Request: invalid credentials
		// 404 Not Found: store doesn't exist
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ShopifyOAuth
}

func (s Scanner) Description() string {
	return "Shopify OAuth credentials (client ID and client secret) are used to authenticate applications with Shopify stores. These credentials can be used to access store data and perform operations on behalf of the application."
}
