package robinhoodcrypto

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	// Reference: https://docs.robinhood.com/crypto/trading/#section/Authentication
	keyPat = regexp.MustCompile(`\b(rh-api-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`)

	// Matches base64 strings. Taken from https://stackoverflow.com/a/475217.
	privKeyBase64Pat = regexp.MustCompile(`(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"rh-api-"}
}

// FromData will find and optionally verify RobinhoodCrypto secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	apiKeyMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		apiKeyMatches[match[1]] = struct{}{}
	}

	base64PrivateKeyMatches := make(map[string]struct{})
	for _, match := range privKeyBase64Pat.FindAllString(dataStr, -1) {
		base64PrivateKeyMatches[match] = struct{}{}
	}

	for apiKey := range apiKeyMatches {
		for base64PrivateKey := range base64PrivateKeyMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_RobinhoodCrypto,
				Raw:          []byte(apiKey),
				RawV2:        []byte(apiKey + base64PrivateKey),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, extraData, verificationErr := verifyMatch(ctx, client, apiKey, base64PrivateKey)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr, apiKey, base64PrivateKey)
			}

			results = append(results, s1)
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, apiKey, base64PrivateKey string) (
	bool, map[string]string, error,
) {
	// Decode the base64 private key.
	privateBytes, err := base64.StdEncoding.DecodeString(base64PrivateKey)
	if err != nil {
		return false, nil, fmt.Errorf("failed to decode base64 private key: %w", err)
	}

	// Sanity check the private key length.
	if len(privateBytes) < 32 {
		return false, nil, fmt.Errorf("private key is too short, expected at least 32 bytes, got %d", len(privateBytes))
	}

	// Create the private key from the seed.
	privateKey := ed25519.NewKeyFromSeed(privateBytes[:32])

	// Draft the message to be signed.
	// Reference: https://docs.robinhood.com/crypto/trading/#section/Authentication/Headers-and-Signature
	var (
		timestamp = fmt.Sprint(time.Now().UTC().Unix())
		path      = "/api/v1/crypto/trading/accounts/"
		method    = http.MethodGet
		body      = ""
	)

	message := apiKey + timestamp + path + method + body
	signature := ed25519.Sign(privateKey, []byte(message))

	req, err := http.NewRequestWithContext(ctx, method, "https://trading.robinhood.com/"+path, strings.NewReader(body))
	if err != nil {
		return false, nil, err
	}

	// Set the required headers.
	headers := map[string]string{
		"x-api-key":   apiKey,
		"x-signature": base64.StdEncoding.EncodeToString(signature),
		"x-timestamp": timestamp,
	}
	for key, value := range headers {
		req.Header.Add(key, value)
	}

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	// StatusOK: The secret is verified.
	case http.StatusOK:
		// Include the additional information returned by the endpoint.
		if len(res.Header) > 0 && res.Header.Get("Content-Type") == "application/json" {
			response := struct {
				AccountNumber       string `json:"account_number"`
				Status              string `json:"status"`
				BuyingPower         string `json:"buying_power"`
				BuyingPowerCurrency string `json:"buying_power_currency"`
			}{}

			if err = json.NewDecoder(res.Body).Decode(&response); err != nil {
				return true, nil, fmt.Errorf("failed to obtain additional information: %w", err)
			}

			return true, map[string]string{"Robinhood Crypto Account Number": response.AccountNumber}, nil
		}

		// The secret is verified, but there is no additional information.
		return true, nil, nil

	// StatusForbidden: The secret is valid, but the credentials do not have access to the endpoint.
	case http.StatusForbidden:
		return true, map[string]string{"Explanation": "Valid credentials without access to Get Crypto Trading Account Details API"}, nil

	// StatusUnauthorized:
	// Two scenarios can happen,
	// 		1. The secret is verified, but is currently inactive.
	// 		2. The secret is determinately not verified.
	case http.StatusUnauthorized:
		// Check if the secret is verified but currently inactive.
		// We want to handle this case because an inactive secret can be activated in the future, at which point it
		// becomes a security risk.
		if len(res.Header) > 0 && res.Header.Get("Content-Type") == "text/plain" {
			body, err := io.ReadAll(res.Body)
			if err != nil {
				// The secret is considered verified but inactive only if the body suggests so. Since the body is not
				// readable, we cannot determine if the secret is verified but inactive.
				return false, nil, fmt.Errorf("failed to read response body: %w", err)
			}

			if strings.TrimSpace(string(body)) == "API credential is not active." {
				return true, map[string]string{"Explanation": "Valid credentials in inactive state"}, nil
			}
		}

		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_RobinhoodCrypto
}

func (s Scanner) Description() string {
	return "Robinhood Crypto API keys can be used to access and trade cryptocurrencies on the Robinhood platform."
}
