package mercadopago

import (
	"context"
	"fmt"
	"io"
	"net/http"

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

	// Access Token: APP_USR-{16-digit-userid}-{6-digit-date}-{32-char-hex-hash}__XX_XX__-{merchant-id}
	// Example: APP_USR-1234567890123456-010122-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6__LA_LD__-987654321
	accessTokenPat = regexp.MustCompile(`\b(APP_USR-\d{16}-\d{6}-[a-f0-9]{32}__[A-Z]{2}_[A-Z]{2}__-\d+)\b`)

	// Public Key: APP_USR-{uuid}
	// Example: APP_USR-12345678-1234-1234-1234-123456789abc
	publicKeyPat = regexp.MustCompile(`\b(APP_USR-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"APP_USR-"}
}

// FromData will find and optionally verify MercadoPago secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Find access tokens (high-severity secrets).
	uniqueAccessTokens := make(map[string]struct{})
	for _, match := range accessTokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAccessTokens[match[1]] = struct{}{}
	}

	for token := range uniqueAccessTokens {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_MercadoPago,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"access_token": token},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyAccessToken(ctx, client, token)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, token)
		}

		results = append(results, s1)
	}

	// Find public keys (low-risk, useful for context).
	uniquePublicKeys := make(map[string]struct{})
	for _, match := range publicKeyPat.FindAllStringSubmatch(dataStr, -1) {
		uniquePublicKeys[match[1]] = struct{}{}
	}

	for key := range uniquePublicKeys {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_MercadoPago,
			Raw:          []byte(key),
			SecretParts:  map[string]string{"public_key": key},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyPublicKey(ctx, client, key)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, key)
		}

		results = append(results, s1)
	}

	return
}

// verifyAccessToken verifies a MercadoPago access token by querying the payments search API.
// This is a read-only endpoint that returns payment data or an empty results array.
func verifyAccessToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.mercadopago.com/v1/payments/search?limit=1", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

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
		// Invalid or expired token — determinately not verified.
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

// verifyPublicKey verifies a MercadoPago public key by querying the payment methods API.
// Public keys have lower privileges but can still access some account info.
func verifyPublicKey(ctx context.Context, client *http.Client, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.mercadopago.com/v1/payment_methods", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+key)

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
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_MercadoPago
}

func (s Scanner) Description() string {
	return "MercadoPago is the leading payment processing platform in Latin America. Access tokens (APP_USR-*) provide full access to merchant payment processing, transaction history, and customer data."
}
