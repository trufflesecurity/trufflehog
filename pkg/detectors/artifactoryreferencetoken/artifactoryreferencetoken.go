package artifactoryreferencetoken

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
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

	defaultClient = common.SaneHttpClient()

	// Reference tokens are base64-encoded strings starting with "reftkn:01|<version>:<expiry>:<random>"
	// The base64 encoding of "reftkn" is "cmVmdGtu", total length is always 64 characters
	tokenPat = regexp.MustCompile(`\b(cmVmdGtu[A-Za-z0-9]{56})\b`)
	urlPat   = regexp.MustCompile(`\b([A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9]\.jfrog\.io)`)

	invalidHosts = simple.NewCache[struct{}]()
	errNoHost    = errors.New("no such host")
)

func (Scanner) CloudEndpoint() string { return "" }

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"cmVmdGtu"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// FromData will find and optionally verify Artifactory Reference tokens in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueTokens, uniqueUrls = make(map[string]struct{}), make(map[string]struct{})

	for _, match := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[match[1]] = struct{}{}
	}

	foundUrls := make([]string, 0)
	for _, match := range urlPat.FindAllStringSubmatch(dataStr, -1) {
		foundUrls = append(foundUrls, match[1])
	}

	// Add found + configured endpoints to the list
	for _, endpoint := range s.Endpoints(foundUrls...) {
		// If any configured endpoint has `https://` remove it because we append that during verification
		endpoint = strings.TrimPrefix(endpoint, "https://")
		uniqueUrls[endpoint] = struct{}{}
	}

	for token := range uniqueTokens {
		for url := range uniqueUrls {
			if invalidHosts.Exists(url) {
				delete(uniqueUrls, url)
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_ArtifactoryReferenceToken,
				Raw:          []byte(token),
				RawV2:        []byte(token + url),
			}

			if verify {
				isVerified, verificationErr := verifyToken(ctx, s.getClient(), url, token)
				s1.Verified = isVerified
				if verificationErr != nil {
					if errors.Is(verificationErr, errNoHost) {
						invalidHosts.Set(url, struct{}{})
						continue
					}

					s1.SetVerificationError(verificationErr, token)
				}

				if isVerified {
					s1.AnalysisInfo = map[string]string{
						"domain": url,
						"token":  token,
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyToken(ctx context.Context, client *http.Client, host, token string) (bool, error) {
	// https://jfrog.com/help/r/jfrog-rest-apis/get-token-by-id
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+host+"/access/api/v1/tokens/me", http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return false, errNoHost
		}
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		// JFrog returns 200 with HTML for invalid subdomains, so we need to check Content-Type
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "application/json") {
			return true, nil
		}
		// HTML response indicates invalid subdomain/redirect - treat as invalid host
		return false, errNoHost
	case http.StatusForbidden:
		// 403 - the authenticated principal has no permissions to get the token
		return true, nil
	case http.StatusUnauthorized:
		// 401 - invalid/expired token
		return false, nil
	default:
		// 404 - endpoint not found (possibly wrong URL or old Artifactory version)
		// 302 and 500+
		return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ArtifactoryReferenceToken
}

func (s Scanner) Description() string {
	return "JFrog Artifactory is a binary repository manager. Reference tokens are 64-character access tokens that can be used to authenticate API requests, providing access to repositories, builds, and artifacts."
}
