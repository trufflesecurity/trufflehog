package amadeus

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"amadeus"}) + `\b([0-9A-Za-z]{32})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"amadeus"}) + `\b([0-9A-Za-z]{16})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"amadeus"}
}

// FromData will find and optionally verify Amadeus secrets in a given set of bytes.
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
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Amadeus,
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
	payload := strings.NewReader("grant_type=client_credentials&client_id=" + key + "&client_secret=" + secret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://test.api.amadeus.com/v1/security/oauth2/token", payload)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
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
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}
		body := string(bodyBytes)
		if !strings.Contains(body, "access_token") {
			return false, nil
		}
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Amadeus
}

func (s Scanner) Description() string {
	return "Amadeus provides travel technology solutions. Amadeus API keys can be used to access and modify travel-related data and services."
}
