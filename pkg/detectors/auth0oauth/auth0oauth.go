package auth0oauth

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
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = detectors.DetectorHttpClientWithLocalAddresses

	clientIdPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"auth0"}) + `\b([a-zA-Z0-9_-]{32,60})\b`)
	clientSecretPat = regexp.MustCompile(`\b([a-zA-Z0-9_-]{64,})\b`)
	domainPat       = regexp.MustCompile(`\b([a-zA-Z0-9][a-zA-Z0-9._-]*auth0\.com)\b`) // could be part of url
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"auth0"}
}

// FromData will find and optionally verify Auth0oauth secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	uniqueDomainMatches := make(map[string]struct{})
	uniqueClientIDs := make(map[string]struct{})
	uniqueSecrets := make(map[string]struct{})
	for _, m := range domainPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueDomainMatches[strings.TrimSpace(m[1])] = struct{}{}
	}
	for _, m := range clientIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueClientIDs[strings.TrimSpace(m[1])] = struct{}{}
	}
	for _, m := range clientSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecrets[strings.TrimSpace(m[1])] = struct{}{}
	}

	for clientIdRes := range uniqueClientIDs {
		for clientSecretRes := range uniqueSecrets {
			for domainRes := range uniqueDomainMatches {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Auth0oauth,
					Redacted:     clientIdRes,
					Raw:          []byte(clientSecretRes),
					RawV2:        []byte(clientIdRes + clientSecretRes),
				}

				if verify {

					client := s.client
					if client == nil {
						client = defaultClient
					}

					isVerified, err := verifyTuple(ctx, client, domainRes, clientIdRes, clientSecretRes)
					if err != nil {
						s1.SetVerificationError(err, clientIdRes)
					}
					s1.Verified = isVerified
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func verifyTuple(ctx context.Context, client *http.Client, domainRes, clientId, clientSecret string) (bool, error) {
	/*
	   curl --request POST \
	     --url 'https://YOUR_DOMAIN/oauth/token' \
	     --header 'content-type: application/x-www-form-urlencoded' \
	     --data 'grant_type=authorization_code&client_id=W44JmL3qD6LxHeEJyKe9lMuhcwvPOaOq&client_secret=YOUR_CLIENT_SECRET&code=AUTHORIZATION_CODE&redirect_uri=undefined'
	*/

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientId)
	data.Set("client_secret", clientSecret)
	data.Set("code", "AUTHORIZATION_CODE")
	data.Set("redirect_uri", "undefined")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+domainRes+"/oauth/token", strings.NewReader(data.Encode())) // URL-encoded payload
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
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
		// This condition will never meet due to invalid request body
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	case http.StatusForbidden:
		// cross check about 'invalid_grant' or 'unauthorized_client' in response body
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}
		bodyStr := string(bodyBytes)
		if strings.Contains(bodyStr, "invalid_grant") || strings.Contains(bodyStr, "unauthorized_client") {
			return true, nil
		}
		return false, nil
	case http.StatusNotFound:
		// domain does not exists - 404 not found
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Auth0oauth
}

func (s Scanner) Description() string {
	return "Auth0 is a service designed to handle authentication and authorization for users. Oauth API keys can be used to impersonate applications and other things related to Auth0's API"
}
