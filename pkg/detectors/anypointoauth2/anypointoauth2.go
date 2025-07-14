package anypointoauth2

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
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"anypoint", "id"}) + `\b([0-9a-f]{32})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"anypoint", "secret"}) + `\b([0-9a-fA-F]{32})\b`)

	verificationUrl = "https://anypoint.mulesoft.com/accounts/oauth2/token"
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"anypoint"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Anypoint secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueIDs, uniqueSecrets = make(map[string]struct{}), make(map[string]struct{})

	for _, matches := range idPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueIDs[matches[1]] = struct{}{}
	}

	for _, matches := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecrets[matches[1]] = struct{}{}
	}

	for id := range uniqueIDs {
		for secret := range uniqueSecrets {
			if id == secret {
				// Avoid processing the same string for both id and secret.
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AnypointOAuth2,
				Raw:          []byte(secret),
				RawV2:        []byte(fmt.Sprintf("%s:%s", id, secret)),
			}

			if verify {
				client := s.getClient()
				isVerified, verificationErr := verifyMatch(ctx, client, id, secret)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)

			}

			results = append(results, s1)

			if s1.Verified {
				// Anypoint client IDs and secrets are mapped one-to-one, so if a pair
				// is verified, we can remove that secret from the uniqueSecrets map.
				delete(uniqueSecrets, secret)
				break
			}
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, id, secret string) (bool, error) {
	payload := strings.NewReader(`{"grant_type":"client_credentials","client_id":"` + id + `","client_secret":"` + secret + `"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verificationUrl, payload)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	// The endpoint responds with status 200 for valid Organization credentials and 422 for Client credentials.
	case http.StatusOK, http.StatusUnprocessableEntity:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AnypointOAuth2
}

func (s Scanner) Description() string {
	return "Anypoint is a unified platform that allows organizations to build and manage APIs and integrations. Anypoint credentials can be used to access and manipulate these integrations and API data."
}
