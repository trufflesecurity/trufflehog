package zendeskapi

import (
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = detectors.DetectorHttpClientWithNoLocalAddresses

	token  = regexp.MustCompile(detectors.PrefixRegex([]string{"zendesk"}) + `([A-Za-z0-9_-]{40})`)
	email  = regexp.MustCompile(`\b([a-zA-Z-0-9-]{5,16}\@[a-zA-Z-0-9]{4,16}\.[a-zA-Z-0-9]{3,6})\b`)
	domain = regexp.MustCompile(`\b([a-zA-Z-0-9]{3,25}\.zendesk\.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"zendesk"}
}

// FromData will find and optionally verify ZendeskApi secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueEmails, uniqueTokens, uniqueDomains = make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})

	for _, match := range email.FindAllStringSubmatch(dataStr, -1) {
		uniqueEmails[match[1]] = struct{}{}
	}

	for _, match := range token.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[match[1]] = struct{}{}
	}

	for _, match := range domain.FindAllStringSubmatch(dataStr, -1) {
		uniqueDomains[match[1]] = struct{}{}
	}

	for token := range uniqueTokens {
		for email := range uniqueEmails {
			for domain := range uniqueDomains {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ZendeskApi,
					Raw:          []byte(token),
				}

				if verify {
					isVerified, verificationErr := verifyZendesk(ctx, client, email, token, domain)
					s1.Verified = isVerified
					s1.SetVerificationError(verificationErr, token)
				}

				results = append(results, s1)

			}
		}

	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ZendeskApi
}

func (s Scanner) Description() string {
	return "Zendesk is a customer service platform. Zendesk API tokens can be used to access and modify customer service data."
}

func verifyZendesk(ctx context.Context, client *http.Client, email, token, domain string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/api/v2/users.json", http.NoBody)
	if err != nil {
		return false, err
	}

	// docs: https://developer.zendesk.com/api-reference/introduction/security-and-auth/
	req.SetBasicAuth(email+"/token", token)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
