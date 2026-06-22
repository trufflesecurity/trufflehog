package user

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
}

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector           = (*Scanner)(nil)
	_ detectors.EndpointCustomizer = (*Scanner)(nil)

	defaultClient = detectors.NewClientWithDedup(detectors.DetectorHttpClientWithNoLocalAddresses)

	keyPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"user"}) + `\b([A-Za-z0-9]{64})\b`)
	userURLPat = regexp.MustCompile(`\b([a-z0-9-]+\.user\.com)\b`)

	invalidHosts = simple.NewCache[struct{}]()
	errNoHost    = errors.New("no such host")
)

func (Scanner) CloudEndpoint() string { return "" }

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"user.com"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify User secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueTokens, uniqueURLs = make(map[string]struct{}), make(map[string]struct{})

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[strings.TrimSpace(match[1])] = struct{}{}
	}

	var foundURLs = make([]string, 0)
	for _, match := range userURLPat.FindAllStringSubmatch(dataStr, -1) {
		foundURLs = append(foundURLs, match[1])
	}

	// Merge found endpoints with any user-configured endpoints.
	// Callers must call UseFoundEndpoints(true) to include endpoints extracted from data.
	for _, endpoint := range s.Endpoints(foundURLs...) {
		endpoint = strings.TrimPrefix(endpoint, "https://")
		uniqueURLs[endpoint] = struct{}{}
	}

	for token := range uniqueTokens {
		for hostname := range uniqueURLs {
			if invalidHosts.Exists(hostname) {
				delete(uniqueURLs, hostname)
				continue
			}

			endpointURL := url.URL{Scheme: "https", Host: hostname}
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_User,
				Raw:          []byte(token),
				RawV2:        []byte(token + ":" + endpointURL.String()),
				SecretParts: map[string]string{
					"key":      token,
					"endpoint": endpointURL.String(),
				},
			}

			if verify {
				isVerified, verificationErr := verifyUserToken(ctx, s.getClient(), hostname, token)
				s1.Verified = isVerified
				if verificationErr != nil {
					if errors.Is(verificationErr, errNoHost) {
						invalidHosts.Set(hostname, struct{}{})
						continue
					}
					s1.SetVerificationError(verificationErr, token)
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyUserToken(ctx context.Context, client *http.Client, hostname, token string) (bool, error) {
	u := url.URL{Scheme: "https", Host: hostname, Path: "/api/public/users/"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", token))

	res, err := detectors.DoWithDedup(client, detector_typepb.DetectorType_User, token+":"+hostname, req)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return false, errNoHost
		}
		return false, err
	}
	defer func() { _ = res.Body.Close() }()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusGone:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_User
}

func (s Scanner) Description() string {
	return "User credentials can be used to authenticate and authorize actions within the User service, potentially allowing access to sensitive data and operations."
}
