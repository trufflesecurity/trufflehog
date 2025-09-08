package fibery

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

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

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"fibery"}) + `\b([0-9a-f]{8}\.[0-9a-f]{35})\b`)
	domainPat = regexp.MustCompile(`(?:https?:\/\/)?([a-zA-Z0-9-]{1,63})\.fibery\.io(?:\/.*)?`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{".fibery.io"}
}

// Description returns a description for the result being detected
func (s Scanner) Description() string {
	return "Fibery is a work management platform that combines various tools for project management, knowledge management, and software development. Fibery API tokens can be used to access and modify data within a Fibery workspace."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Fibery secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueSecrets := make(map[string]struct{})
	uniqueDomains := make(map[string]struct{})

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecrets[match[1]] = struct{}{}
	}
	for _, match := range domainPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueDomains[match[1]] = struct{}{}
	}

	for secret := range uniqueSecrets {
		for domain := range uniqueDomains {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Fibery,
				Raw:          []byte(secret),
			}

			if verify {
				isVerified, verificationErr := verifyMatch(ctx, s.getClient(), secret, domain)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, secret, domain)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, secret, domain string) (bool, error) {
	timeout := 10 * time.Second
	client.Timeout = timeout
	url := fmt.Sprintf("https://%s.fibery.io/api/commands", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Token %s", secret))
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
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Fibery
}
