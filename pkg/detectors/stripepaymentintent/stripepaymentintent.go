package stripepaymentintent

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
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	Client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	clientSecretPat   = regexp.MustCompile(`\b(pi_[a-zA-Z0-9]{24}_secret_[a-zA-Z0-9]{25})\b`)
	secretKeyPat      = regexp.MustCompile(`\b([rs]k_live_[a-zA-Z0-9]{20,247})\b`)
	publishableKeyPat = regexp.MustCompile(`\b(pk_live_[a-zA-Z0-9]{20,247})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"_secret_"}
}

func (s Scanner) getClient() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return defaultClient
}

// FromData will find and optionally verify Stripe Payment Intent secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)

	// Stripe client secrets can't be verified on their own, they must be paired with a secret or publishable key.
	// Secret keys are preferred for verification, but in some real-world cases only publishable keys are present.
	// While typically used client-side, publishable keys can still confirm certain PaymentIntents.
	// To avoid missing valid detections, we verify using both key types.
	// If no keys are found, we skip detection since client secrets alone are not actionable.
	clientSecrets := extractMatches(clientSecretPat, dataStr)
	secretKeys := extractMatches(secretKeyPat, dataStr)
	publishableKeys := extractMatches(publishableKeyPat, dataStr)

	results := make([]detectors.Result, 0, len(clientSecrets)*(len(secretKeys)+len(publishableKeys)))

	// Process each client secret against all keys
	for clientSecret := range clientSecrets {
		for key := range secretKeys {
			result := detectors.Result{
				DetectorType: detectorspb.DetectorType_StripePaymentIntent,
				Raw:          []byte(clientSecret),
				RawV2:        []byte(clientSecret + key),
				ExtraData: map[string]string{
					"key_type": "secret",
				},
			}

			if verify {
				verified, err := verifyPaymentIntentWithSecretKey(ctx, s.getClient(), clientSecret, key)
				result.Verified = verified
				result.SetVerificationError(err)
			}

			results = append(results, result)
		}

		for key := range publishableKeys {
			result := detectors.Result{
				DetectorType: detectorspb.DetectorType_StripePaymentIntent,
				Raw:          []byte(clientSecret),
				RawV2:        []byte(clientSecret + key),
				ExtraData: map[string]string{
					"key_type": "publishable",
				},
			}

			if verify {
				verified, err := verifyPaymentIntentWithPublishableKey(ctx, s.getClient(), clientSecret, key)
				result.Verified = verified
				result.SetVerificationError(err)
			}

			results = append(results, result)
		}
	}

	return results, nil
}

// Helper function to extract matches into a map for uniqueness
func extractMatches(pattern *regexp.Regexp, data string) map[string]struct{} {
	matches := pattern.FindAllStringSubmatch(data, -1)
	result := make(map[string]struct{}, len(matches))

	for _, match := range matches {
		if len(match) >= 2 {
			result[match[1]] = struct{}{}
		}
	}

	return result
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_StripePaymentIntent
}

func (s Scanner) Description() string {
	return "Stripepaymentintent objects represent a customer's intent to pay and track the lifecycle of a payment. These objects are used to initiate and manage payment flows, including confirmation, authentication, and capture of funds."
}

// VerifyPaymentIntentWithSecretKey verifies a Stripe PaymentIntent using the secret key.
// It checks if the PaymentIntent ID is valid and if the secret key has access to it.
// It returns a VerificationResult indicating the validity of the PaymentIntent and any error messages.
func verifyPaymentIntentWithSecretKey(ctx context.Context, client *http.Client, clientSecret, secretKey string) (bool, error) {
	url := fmt.Sprintf("https://api.stripe.com/v1/payment_intents/%s", extractIntentID(clientSecret))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", secretKey))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("request failed: %v", err)
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return isClientSecretValid(resp.Body, clientSecret)
	case http.StatusUnauthorized, http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

// verifyPaymentIntentWithPublishableKey verifies a Stripe PaymentIntent using the publishable key.
// It checks if the PaymentIntent ID is valid and if the publishable key has access to it.
// It returns a VerificationResult indicating the validity of the PaymentIntent and any error messages.
// Note: It should only be used for client-side verification or in scenarios where the secret key is unavailable.
func verifyPaymentIntentWithPublishableKey(ctx context.Context, client *http.Client, clientSecret, publishableKey string) (bool, error) {
	paymentIntentId := extractIntentID(clientSecret)
	if paymentIntentId == "" {
		return false, fmt.Errorf("payment intent ID is required")
	}

	// Construct the request URL and add publishable key as a query parameter (this is how Stripe.js works)
	url := fmt.Sprintf("https://api.stripe.com/v1/payment_intents/%s", paymentIntentId)
	url = url + fmt.Sprintf("?key=%s", publishableKey)
	url = url + fmt.Sprintf("&client_secret=%s", clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("error creating request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("request failed: %v", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return isClientSecretValid(resp.Body, clientSecret)
	case http.StatusUnauthorized, http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func extractIntentID(clientSecret string) string {
	parts := strings.SplitN(clientSecret, "_secret_", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

func isClientSecretValid(body io.Reader, expectedSecret string) (bool, error) {
	var respBody struct {
		ClientSecret string `json:"client_secret"`
	}

	if err := json.NewDecoder(body).Decode(&respBody); err != nil {
		return false, fmt.Errorf("failed to decode response body: %v", err)
	}

	return respBody.ClientSecret == expectedSecret, nil
}
