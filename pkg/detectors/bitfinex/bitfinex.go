package bitfinex

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
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
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// related resource https://medium.com/@Bitfinex/api-development-update-april-65fe52f84124
	apiKeyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"bitfinex"}) + `\b([A-Za-z0-9_-]{43})\b`)
	apiSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bitfinex"}) + `\b([A-Za-z0-9_-]{43})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"bitfinex"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Bitfinex
}

func (s Scanner) Description() string {
	return "Bitfinex is a cryptocurrency exchange offering various trading options. Bitfinex API keys can be used to access and manage trading accounts."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// FromData will find and optionally verify Bitfinex secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueAPIKeys, uniqueAPISecrets = make(map[string]struct{}), make(map[string]struct{})

	for _, apiKey := range apiKeyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAPIKeys[apiKey[1]] = struct{}{}
	}

	for _, apiSecret := range apiSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAPISecrets[apiSecret[1]] = struct{}{}
	}

	for apiKey := range uniqueAPIKeys {
		for apiSecret := range uniqueAPISecrets {
			// as both patterns are same, avoid verifying same string for both
			if apiKey == apiSecret {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Bitfinex,
				Raw:          []byte(apiKey),
			}

			if verify {
				isVerified, verificationErr := verifyBitfinex(ctx, s.getClient(), apiKey, apiSecret)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

// docs: https://docs.bitfinex.com/docs/introduction
func verifyBitfinex(ctx context.Context, client *http.Client, apiKey, apiSecret string) (bool, error) {
	baseURL := "https://api.bitfinex.com"
	requestPath := "/v2/auth/r/wallets"
	signaturePath := "/api" + requestPath
	nonce := fmt.Sprintf("%d", time.Now().UnixNano()/int64(time.Microsecond))
	body := "{}"
	signaturePayload := signaturePath + nonce + body
	signature, err := sign(signaturePayload, apiSecret)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+requestPath, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("bfx-apikey", apiKey)
	req.Header.Set("bfx-signature", signature)
	req.Header.Set("bfx-nonce", nonce)

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
	case http.StatusInternalServerError:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}

		if strings.Contains(string(body), "apikey: digest invalid") || strings.Contains(string(body), "apikey: invalid") {
			return false, nil
		} else {
			return false, fmt.Errorf("failed to verify Bitfinex API key, error: %s", string(body))
		}
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

func sign(msg, apiSecret string) (string, error) {
	sig := hmac.New(sha512.New384, []byte(apiSecret))
	_, err := sig.Write([]byte(msg))
	if err != nil {
		return "", nil
	}
	return hex.EncodeToString(sig.Sum(nil)), nil
}
