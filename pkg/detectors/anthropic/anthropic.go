package anthropic

import (
	"context"
	"encoding/json"
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
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	//
	// Anthropic issues three credential shapes under the sk-ant- prefix: API keys
	// (sk-ant-api03-, 95-char payload ending in AA), admin keys (sk-ant-admin01-,
	// same shape), and OAuth access tokens minted by `claude setup-token` for
	// Claude Pro/Max subscribers (sk-ant-oat01-). Anthropic does not publish an
	// exact length for the OAuth payload, so it is matched with a minimum length
	// instead of an exact one (the same trade-off the googleoauth2 detector makes
	// for access tokens): 20 base64url chars weeds out placeholders like
	// sk-ant-oat01-abc123 while the distinctive 15-char prefix keeps false
	// positives low. The trailing \b applies only to the fixed-length
	// API/admin-key alternative: the OAuth payload is base64url and may end
	// in '-', which is a non-word character, so a trailing \b would make the
	// matcher backtrack and drop a trailing hyphen, truncating the secret
	// before verification.
	keyPat = regexp.MustCompile(`\b(sk-ant-(?:admin01|api03)-[\w\-]{93}AA\b|sk-ant-oat01-[\w\-]{20,})`)

	// verification endpoints
	apiKeyEndpoint   = "https://api.anthropic.com/v1/models"
	adminKeyEndpoint = "https://api.anthropic.com/v1/organizations/api_keys"
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sk-ant-api03", "sk-ant-admin01", "sk-ant-oat01"}
}

// FromData will find and optionally verify Anthropic secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keys := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, key := range keys {
		keyMatch := strings.TrimSpace(key[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Anthropic,
			Raw:          []byte(keyMatch),
			ExtraData:    make(map[string]string),
			SecretParts:  map[string]string{"key": keyMatch},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			var (
				isVerified      bool
				verificationErr error
			)

			if isAdminKey(keyMatch) {
				s1.ExtraData["Type"] = "Admin Key"
				isVerified, verificationErr = verifyAnthropicKey(ctx, client, adminKeyEndpoint, keyMatch)
			} else if isOAuthToken(keyMatch) {
				s1.ExtraData["Type"] = "OAuth Token"
				isVerified, verificationErr = verifyOAuthToken(ctx, client, keyMatch)
			} else {
				s1.ExtraData["Type"] = "API Key"
				isVerified, verificationErr = verifyAnthropicKey(ctx, client, apiKeyEndpoint, keyMatch)
			}

			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, keyMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

/*
verifyAnthropicKey verify the anthropic key passed against the endpoint

Endpoints:

  - For api keys: https://docs.anthropic.com/en/api/models-list

  - For admin keys:  https://docs.anthropic.com/en/api/admin-api/apikeys/list-api-keys
*/
func verifyAnthropicKey(ctx context.Context, client *http.Client, endpoint, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Set("x-api-key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")

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

	case http.StatusNotFound, http.StatusUnauthorized:
		// 404 is returned if api key is disabled or not found
		return false, nil

	default:
		// A 400 is invalid_request_error, never a bad-key signal (that's always 401),
		// so it must stay indeterminate rather than count as not-live.
		return false, apiError(res)
	}
}

/*
verifyOAuthToken verifies a Claude Code OAuth access token (sk-ant-oat01-)
against the read-only models endpoint.

OAuth tokens are sent as Authorization: Bearer (API keys use x-api-key), and
OAuth-authenticated requests must carry the oauth-2025-04-20 beta header;
without it the API rejects even live tokens, so the header is part of the
verification contract. The status semantics mirror verifyAnthropicKey: 200 is
verified, 401/404 is determinate not-live, and anything else stays
indeterminate rather than being mislabelled.
*/
func verifyOAuthToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiKeyEndpoint, http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")

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

	case http.StatusNotFound, http.StatusUnauthorized:
		// 404 is returned if the token is disabled or not found
		return false, nil

	default:
		// Same graceful semantics as API keys: an unexpected status is never a
		// bad-token signal, so it must stay indeterminate rather than count as
		// not-live.
		return false, apiError(res)
	}
}

// anthropicErrorResponse is the Anthropic API's error envelope for non-2xx responses.
// See https://platform.claude.com/docs/en/api/errors.
type anthropicErrorResponse struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

const maxErrorBodySize = 4 << 10 // cap how much of the error body we bother parsing

// apiError enriches an unexpected status with the API's own error type/message when present.
func apiError(res *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(res.Body, maxErrorBodySize))
	if err != nil {
		return fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	var apiErr anthropicErrorResponse
	if err := json.Unmarshal(body, &apiErr); err != nil || apiErr.Error.Type == "" {
		return fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	return fmt.Errorf("unexpected HTTP response status %d (%s: %s)",
		res.StatusCode, apiErr.Error.Type, apiErr.Error.Message)
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Anthropic
}

func (s Scanner) Description() string {
	return "Anthropic is an AI research company. The API keys can be used to access their AI models and services."
}

func isAdminKey(key string) bool {
	return strings.HasPrefix(key, "sk-ant-admin01")
}

func isOAuthToken(key string) bool {
	return strings.HasPrefix(key, "sk-ant-oat01")
}
