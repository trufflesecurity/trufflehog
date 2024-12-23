package godaddy

import (
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	v1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/godaddy/v1"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

var (
	// ensure the scanner satisfies the interface at compile time.
	_ detectors.Detector  = (*Scanner)(nil)
	_ detectors.Versioner = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	// the key for the GoDaddy Prod environment is a 35-character alphanumeric string that may include underscores.
	keyPattern = regexp.MustCompile(detectors.PrefixRegex([]string{"godaddy"}) + common.BuildRegex("a-zA-Z0-9", "_", 35))
	// the secret for the GoDaddy Prod environment is a 22-character alphanumeric string.
	secretPattern = regexp.MustCompile(detectors.PrefixRegex([]string{"godaddy"}) + common.BuildRegex("a-zA-Z0-9", "", 22))

	// prod environment
	prod = "api.godaddy.com"
)

func (s *Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

func (s *Scanner) Version() int { return 2 }

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"godaddy"}
}

func (s Scanner) Description() string {
	return "GoDaddy offers website building, hosting and security tools and services to construct, expand and protect the online presence." +
		"GoDaddy provides applications and access to relevant third-party products and platforms to connect their customers"
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GoDaddy
}

// FromData will find and optionally verify GoDaddy API Key and secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	// convert the data to string
	dataStr := string(data)

	// find all the matching keys and secret in data and make a unique maps of both keys and secret.
	uniqueKeys, uniqueSecrets := make(map[string]struct{}), make(map[string]struct{})

	for _, foundKey := range keyPattern.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[foundKey[1]] = struct{}{}
	}

	for _, foundSecret := range secretPattern.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecrets[foundSecret[1]] = struct{}{}
	}

	for key := range uniqueKeys {
		for secret := range uniqueSecrets {
			result := detectors.Result{
				DetectorType: detectorspb.DetectorType_GoDaddy,
				Raw:          []byte(key),
				ExtraData:    make(map[string]string),
			}

			if verify {
				isVerified, verificationErr := VerifyGoDaddySecret(ctx, s.getClient(), prod, v1.MakeAuthHeaderValue(key, secret))

				result.Verified = isVerified
				result.SetVerificationError(verificationErr, secret)

				// in case of successful verification add the enviorement name in extradata to let user know which env this secret belong to.
				if isVerified {
					result.ExtraData["Environment"] = "Prod"
				}
			}

			results = append(results, result)
		}
	}

	return results, nil

}

// VerifyGoDaddySecret make a call to godaddy api with given secret to check if secret is valid or not.
func VerifyGoDaddySecret(ctx context.Context, client *http.Client, environment, secret string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/v1/domains/available?domain=example.com", environment), http.NoBody)
	if err != nil {
		return false, err
	}

	// set the required auth header
	req.Header.Set("Authorization", secret)

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
	case http.StatusUnauthorized:
		return false, nil
	case http.StatusForbidden:
		// as per documentation in case of 403 the token is actually verified but it does not have access.
		return true, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
