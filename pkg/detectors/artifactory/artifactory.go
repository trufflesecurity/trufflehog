package artifactory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
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

	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b([a-zA-Z0-9]{64,73})\b`)
	URLPat = regexp.MustCompile(`\b([A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9]\.jfrog\.io)`)

	invalidHosts = simple.NewCache[struct{}]()

	errNoHost = errors.New("no such host")
)

func (Scanner) CloudEndpoint() string { return "" }

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"artifactory", "jfrog.io"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Artifactory secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueTokens, uniqueUrls = make(map[string]struct{}), make(map[string]struct{})

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[match[1]] = struct{}{}
	}

	var foundUrls = make([]string, 0)

	for _, match := range URLPat.FindAllStringSubmatch(dataStr, -1) {
		foundUrls = append(foundUrls, match[1])
	}

	// add found + configured endpoints to the list
	for _, endpoint := range s.Endpoints(foundUrls...) {
		// if any configured endpoint has `https://` remove it because we append that during verification
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
				DetectorType: detectorspb.DetectorType_ArtifactoryAccessToken,
				Raw:          []byte(token),
				RawV2:        []byte(token + url),
			}

			if verify {
				isVerified, verificationErr := verifyArtifactory(ctx, s.getClient(), url, token)
				s1.Verified = isVerified
				if verificationErr != nil {
					if errors.Is(verificationErr, errNoHost) {
						invalidHosts.Set(url, struct{}{})
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

func verifyArtifactory(ctx context.Context, client *http.Client, resURLMatch, resMatch string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+resURLMatch+"/artifactory/api/system/ping", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("X-JFrog-Art-Api", resMatch)

	resp, err := client.Do(req)
	if err != nil {
		// lookup foo.jfrog.io: no such host
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
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}

		if strings.Contains(string(body), "OK") {
			return true, nil
		}

		return false, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusFound: // 302 can occur if the url is incorrect
		// https://jfrog.com/help/r/jfrog-rest-apis/error-responses
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ArtifactoryAccessToken
}

func (s Scanner) Description() string {
	return "Artifactory is a repository manager that supports all major package formats. Artifactory access tokens can be used to authenticate and perform operations on repositories."
}
