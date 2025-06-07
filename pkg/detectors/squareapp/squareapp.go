package squareapp

import (
	"bytes"
	"context"
	"encoding/json"
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
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()
	/*
		The sandbox id and secret has word `sandbox-` as prefix
		possibly always `sq0csp` for secret and `sq0idb` for app
	*/
	keyPat = regexp.MustCompile(`(?:sandbox-)?sq0i[a-z]{2}-[0-9A-Za-z_-]{22,43}`)
	secPat = regexp.MustCompile(`(?:sandbox-)?sq0c[a-z]{2}-[0-9A-Za-z_-]{40,50}`)

	// api endpoints
	sandboxEndpoint = "https://connect.squareupsandbox.com/oauth2/revoke"
	prodEndpoint    = "https://connect.squareup.com/oauth2/revoke"
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sq0i"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SquareApp
}

func (s Scanner) Description() string {
	return "Square is a financial services and mobile payment company. Square credentials can be used to access and manage payment processing and other financial services."
}

// FromData will find and optionally verify SquareApp secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueIDMatches, uniqueSecretMatches = make(map[string]struct{}), make(map[string]struct{})

	for _, match := range keyPat.FindAllString(dataStr, -1) {
		uniqueIDMatches[match] = struct{}{}
	}

	for _, match := range secPat.FindAllString(dataStr, -1) {
		uniqueSecretMatches[match] = struct{}{}
	}

	for id := range uniqueIDMatches {
		for secret := range uniqueSecretMatches {
			// if both are not from same env, continue
			if !hasSamePrefix(id, secret) {
				continue
			}

			result := detectors.Result{
				DetectorType: detectorspb.DetectorType_SquareApp,
				Raw:          []byte(id),
				Redacted:     id,
				ExtraData:    map[string]string{},
			}

			var isVerified bool
			var verificationErr error

			// verify against sandbox endpoint
			if verify && isSandbox(id) {
				isVerified, verificationErr = verifySquareApp(ctx, client, sandboxEndpoint, id, secret)
				result.ExtraData["Env"] = "Sandbox"
			}

			// verify against prod endpoint
			if verify && !isSandbox(id) {
				isVerified, verificationErr = verifySquareApp(ctx, client, prodEndpoint, id, secret)
				result.ExtraData["Env"] = "Production"
			}

			result.Verified = isVerified
			result.SetVerificationError(verificationErr)

			results = append(results, result)

			// once a secret is verified with id, remove it from the list
			if isVerified {
				delete(uniqueSecretMatches, secret)
			}
		}
	}

	return results, nil
}

func verifySquareApp(ctx context.Context, client *http.Client, endpoint, id, secret string) (bool, error) {
	reqData, err := json.Marshal(map[string]string{
		"client_id":    id,
		"access_token": "fakeTruffleHogAccessTokenForVerification",
	})
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(reqData))
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Client %s", secret))
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return true, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func hasSamePrefix(id, secret string) bool {
	idHasPrefix := strings.HasPrefix(id, "sandbox-")
	secretHasPrefix := strings.HasPrefix(secret, "sandbox-")

	return idHasPrefix == secretHasPrefix
}

// isSandbox check if provided key(id or secret) is of sandbox env
func isSandbox(key string) bool {
	return strings.HasPrefix(key, "sandbox-")
}
