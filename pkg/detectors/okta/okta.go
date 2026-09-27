package okta

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomResultsCleaner = (*Scanner)(nil)

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses
	domainPat     = regexp.MustCompile(`\b[a-z0-9-]{1,40}\.okta(?:preview|-emea){0,1}\.com\b`)
	tokenPat      = regexp.MustCompile(`\b00[a-zA-Z0-9_-]{40}\b`)

	// Okta app/client IDs: "0oa" + 17 base62 characters.
	oauthClientIDPat = regexp.MustCompile(`\b0oa[a-zA-Z0-9]{17}\b`)
	// Delimiters consume a char instead of using \b, since \b breaks on secrets
	// starting/ending in '-' (a non-word char that's also part of the charset).
	oauthClientSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"client_secret", "clientsecret", "client-secret"}) + `(?:^|[^a-zA-Z0-9_-])([a-zA-Z0-9_-]{40,64})(?:[^a-zA-Z0-9_-]|$)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{".okta"}
}

// FromData will find and optionally verify Okta secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueTokens := make(map[string]struct{})
	uniqueDomains := make(map[string]struct{})
	uniqueClientIDs := make(map[string]struct{})
	uniqueClientSecrets := make(map[string]struct{})

	for _, matches := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[matches[0]] = struct{}{}
	}

	for _, matches := range domainPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueDomains[matches[0]] = struct{}{}
	}

	for _, matches := range oauthClientIDPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueClientIDs[matches[0]] = struct{}{}
	}

	for _, matches := range oauthClientSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueClientSecrets[matches[1]] = struct{}{}
	}

	for token := range uniqueTokens {
		for domain := range uniqueDomains {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_Okta,
				Raw:          []byte(token),
				Redacted:     fmt.Sprintf("%s:%s...%s", domain, token[:4], token[len(token)-4:]),
				SecretParts: map[string]string{
					"domain": domain,
					"token":  token,
				},
				RawV2: []byte(fmt.Sprintf("%s:%s", domain, token)),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyOktaToken(ctx, client, domain, token)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)
			}

			results = append(results, s1)
		}
	}

	for clientID := range uniqueClientIDs {
		for clientSecret := range uniqueClientSecrets {
			for domain := range uniqueDomains {
				s2 := detectors.Result{
					DetectorType: detector_typepb.DetectorType_Okta,
					Raw:          []byte(clientSecret),
					Redacted:     fmt.Sprintf("%s:%s", domain, clientID),
					SecretParts: map[string]string{
						"domain":        domain,
						"client_id":     clientID,
						"client_secret": clientSecret,
					},
					RawV2: []byte(fmt.Sprintf("%s:%s:%s", domain, clientID, clientSecret)),
				}

				if verify {
					client := s.client
					if client == nil {
						client = defaultClient
					}

					isVerified, verificationErr := verifyOktaOAuthClientCredentials(ctx, client, domain, clientID, clientSecret)
					s2.Verified = isVerified
					s2.SetVerificationError(verificationErr)
				}

				results = append(results, s2)
			}
		}
	}

	return
}

func verifyOktaToken(ctx context.Context, client *http.Client, domain, token string) (bool, error) {
	// curl -v -X GET \
	// -H "Accept: application/json" \
	// -H "Content-Type: application/json" \
	// -H "Authorization: SSWS token" \
	// "https://subdomain.okta.com/api/v1/users/me"

	url := fmt.Sprintf("https://%s/api/v1/users/me", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("SSWS %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		body, _ := io.ReadAll(resp.Body)
		return strings.Contains(string(body), "\"activated\":"), nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func verifyOktaOAuthClientCredentials(ctx context.Context, client *http.Client, domain, clientID, clientSecret string) (bool, error) {
	// curl -v -X POST \
	// -H "Accept: application/json" \
	// -H "Content-Type: application/x-www-form-urlencoded" \
	// -u "clientID:clientSecret" \
	// -d "grant_type=client_credentials" \
	// "https://subdomain.okta.com/oauth2/default/v1/token"

	const body = "grant_type=client_credentials"

	url := fmt.Sprintf("https://%s/oauth2/default/v1/token", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}
		return strings.Contains(string(respBody), "\"access_token\""), nil
	case http.StatusBadRequest:
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}
		// Okta authenticates the client before grant-type checks, so "unauthorized_client" still confirms the secret.
		if strings.Contains(string(respBody), "unauthorized_client") {
			return true, nil
		}
		if strings.Contains(string(respBody), "invalid_client") {
			return false, nil
		}
		// Other 400s (e.g. invalid_scope) say nothing about the secret; surface as an error.
		return false, fmt.Errorf("response body missing expected keyword")
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

// CleanResults keeps the best (preferably verified) result per distinct secret
// identity (Redacted), rather than collapsing unrelated SSWS and OAuth findings
// down to a single arbitrary result the way detectors.CleanResults would.
func (s Scanner) CleanResults(results []detectors.Result, _ bool) []detectors.Result {
	if len(results) == 0 {
		return results
	}

	byIdentity := make(map[string]detectors.Result, len(results))
	for _, r := range results {
		if r.Verified {
			byIdentity[r.Redacted] = r
			continue
		}
		if _, exists := byIdentity[r.Redacted]; !exists {
			byIdentity[r.Redacted] = r
		}
	}

	cleaned := make([]detectors.Result, 0, len(byIdentity))
	for _, r := range byIdentity {
		cleaned = append(cleaned, r)
	}
	return cleaned
}

func (s Scanner) ShouldCleanResultsIrrespectiveOfConfiguration() bool {
	return false
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Okta
}

func (s Scanner) Description() string {
	return "Okta is an identity and access management service. Okta tokens can be used to authenticate and access various resources and APIs within an organization."
}
