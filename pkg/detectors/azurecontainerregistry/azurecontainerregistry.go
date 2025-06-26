package azurecontainerregistry

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
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	urlPat      = regexp.MustCompile(`([a-z0-9][a-z0-9-]{1,100}[a-z0-9])\.azurecr\.io`)
	passwordPat = regexp.MustCompile(`\b[a-zA-Z0-9+/]{42}\+ACR[a-zA-Z0-9]{6}\b`)

	invalidHosts = simple.NewCache[struct{}]()
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{".azurecr.io"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureContainerRegistry
}

func (s Scanner) Description() string {
	return "Azure's container registry is used to store docker containers. An API key can be used to override existing containers, read sensitive data, and do other operations inside the container registry."
}

// FromData will find and optionally verify Azurecontainerregistry secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	logger := logContext.AddLogger(ctx).Logger().WithName("azurecr")
	dataStr := string(data)

	// Deduplicate matches.
	registryMatches := make(map[string]struct{})
	for _, matches := range urlPat.FindAllStringSubmatch(dataStr, -1) {
		u := matches[1]
		// Ignore https://learn.microsoft.com/en-us/azure/container-registry/container-registry-private-link
		if u == "privatelink" || u == "myacr" {
			continue
		}
		registryMatches[u] = struct{}{}
	}
	passwordMatches := make(map[string]struct{})
	for _, matches := range passwordPat.FindAllStringSubmatch(dataStr, -1) {
		p := matches[0]
		if detectors.StringShannonEntropy(p) < 4 {
			continue
		}
		passwordMatches[p] = struct{}{}
	}

EndpointLoop:
	for username := range registryMatches {
		for password := range passwordMatches {
			r := detectors.Result{
				DetectorType: detectorspb.DetectorType_AzureContainerRegistry,
				Raw:          []byte(password),
				RawV2:        []byte(`{"username":"` + username + `","password":"` + password + `"}`),
				Redacted:     username,
			}

			if verify {
				if invalidHosts.Exists(username) {
					logger.V(3).Info("Skipping invalid registry", "username", username)
					continue EndpointLoop
				}

				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyMatch(ctx, client, username, password)
				if isVerified {
					delete(passwordMatches, password)
					r.Verified = true
				}
				if verificationErr != nil {
					if errors.Is(verificationErr, noSuchHostErr) {
						invalidHosts.Set(username, struct{}{})
						continue EndpointLoop
					}
					r.SetVerificationError(verificationErr, password)
				}
			}

			results = append(results, r)
			if r.Verified {
				break
			}
		}
	}

	return results, nil
}

func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

var noSuchHostErr = errors.New("no such host")

func verifyMatch(ctx context.Context, client *http.Client, username string, password string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s.azurecr.io/v2/", username), nil)
	if err != nil {
		return false, err
	}

	req.SetBasicAuth(username, password)
	res, err := client.Do(req)
	if err != nil {
		// lookup foo.azurecr.io: no such host
		if strings.Contains(err.Error(), "no such host") {
			return false, noSuchHostErr
		}
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified.
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
