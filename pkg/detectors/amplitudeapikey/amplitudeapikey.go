package amplitudeapikey

import (
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
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
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"amplitude"}) + `\b([0-9a-f]{32})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"amplitude"}) + `\b([0-9a-f]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"amplitude"}
}

// FromData will find and optionally verify AmplitudeApiKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueKeys, uniqueSecrets = make(map[string]struct{}), make(map[string]struct{})

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[matches[1]] = struct{}{}
	}

	for _, matches := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecrets[matches[1]] = struct{}{}
	}

	for key := range uniqueKeys {
		for secret := range uniqueSecrets {
			// regex for both key and secret are same so the set of strings could possibly be same as well
			if key == secret {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AmplitudeApiKey,
				Raw:          []byte(key),
				RawV2:        []byte(key + secret),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyAdobeIOSecret(ctx, client, key, secret)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyAdobeIOSecret(ctx context.Context, client *http.Client, key string, secret string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://amplitude.com/api/2/taxonomy/category", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(key, secret)
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AmplitudeApiKey
}

func (s Scanner) Description() string {
	return "Amplitude is a product analytics service that helps companies track and analyze user behavior within web and mobile applications. Amplitude API keys can be used to access and modify this data."
}
