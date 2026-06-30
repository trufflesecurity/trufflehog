package anypointclientsecret

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Anypoint Client ID/Secret patterns - 32 character hex strings
	// Client IDs and Secrets are 32-character hexadecimal strings
	clientIdPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"anypoint", "client", "id"}) + `\b([0-9a-f]{32})\b`)
	clientSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"anypoint", "client", "secret"}) + `\b([0-9a-fA-F]{32})\b`)

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

// FromData will find and optionally verify Anypoint Client ID/Secret pairs in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueClientIDs, uniqueClientSecrets = make(map[string]struct{}), make(map[string]struct{})

	for _, matches := range clientIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueClientIDs[matches[1]] = struct{}{}
	}

	for _, matches := range clientSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueClientSecrets[matches[1]] = struct{}{}
	}

	for clientId := range uniqueClientIDs {
		for clientSecret := range uniqueClientSecrets {
			if clientId == clientSecret {
				// Avoid processing the same string for both client ID and secret.
				continue
			}

			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_AnypointClientSecret,
				Raw:          []byte(clientSecret),
				RawV2:        []byte(fmt.Sprintf("%s:%s", clientId, clientSecret)),
				SecretParts: map[string]string{
					"client_id":     clientId,
					"client_secret": clientSecret,
				},
			}

			if verify {
				client := s.getClient()
				isVerified, verificationErr := verifyMatch(ctx, client, clientId, clientSecret)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)
			}

			results = append(results, s1)

			if s1.Verified {
				// Anypoint client IDs and secrets are mapped one-to-one, so if a pair
				// is verified, we can remove that secret from the uniqueClientSecrets map.
				delete(uniqueClientSecrets, clientSecret)
				break
			}
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, clientId, clientSecret string) (bool, error) {
	payload := strings.NewReader(`{"grant_type":"client_credentials","client_id":"` + clientId + `","client_secret":"` + clientSecret + `"}`)
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

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_AnypointClientSecret
}

func (s Scanner) Description() string {
	return "Anypoint is a unified platform for building and managing APIs and integrations. Anypoint Client ID and Secret credentials can be used to authenticate applications and access API resources."
}
