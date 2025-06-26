package okta

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
	domainPat     = regexp.MustCompile(`\b[a-z0-9-]{1,40}\.okta(?:preview|-emea){0,1}\.com\b`)
	tokenPat      = regexp.MustCompile(`\b00[a-zA-Z0-9_-]{40}\b`)
	// TODO: Oauth client secrets
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{".okta"}
}

// FromData will find and optionally verify Okta secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueTokens, uniqueDomains = make(map[string]struct{}), make(map[string]struct{})

	for _, matches := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[matches[0]] = struct{}{}
	}

	for _, matches := range domainPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueDomains[matches[0]] = struct{}{}
	}

	for token := range uniqueTokens {
		for domain := range uniqueDomains {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Okta,
				Raw:          []byte(token),
				RawV2:        []byte(fmt.Sprintf("%s:%s", domain, token)),
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
	defer resp.Body.Close()

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

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Okta
}

func (s Scanner) Description() string {
	return "Okta is an identity and access management service. Okta tokens can be used to authenticate and access various resources and APIs within an organization."
}
