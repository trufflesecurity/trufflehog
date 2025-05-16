package azureappconfigconnectionstring

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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
	defaultClient       = common.SaneHttpClient()
	connectionStringPat = regexp.MustCompile(`Endpoint=(https:\/\/[a-zA-Z0-9-]+\.azconfig\.io);Id=([a-zA-Z0-9+\/=]+);Secret=([a-zA-Z0-9+\/=]+)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{".azconfig.io"}
}

// FromData will find and optionally verify Azure Management API keys in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatchesUnique := make(map[string][]string)
	for _, keyMatch := range connectionStringPat.FindAllStringSubmatch(dataStr, -1) {
		keyMatchesUnique[strings.TrimSpace(keyMatch[0])] = keyMatch // keep all the matched groups for verification
	}

	for connectionString, connectionInfo := range keyMatchesUnique {
		endpoint := connectionInfo[1] // Endpoint
		id := connectionInfo[2]       //	Id
		secret := connectionInfo[3]   // Secret
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_AzureAppConfigConnectionString,
			Raw:          []byte(id),
			RawV2:        []byte(connectionString),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := s.verifyMatch(ctx, client, endpoint, id, secret)
			s1.Verified = isVerified

			if verificationErr != nil && !strings.Contains(verificationErr.Error(), "no such host") { // ignore no such host errors
				s1.SetVerificationError(verificationErr, connectionString)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureAppConfigConnectionString
}

func (s Scanner) Description() string {
	return "Azure App Configuration is a managed service that centralizes application settings and feature flags, enabling dynamic updates without redeploying applications. Its connection string, which includes the endpoint URL and an access key, securely connects applications to the configuration store."
}

// generateHMACSignature creates the HMAC-SHA256 signature
func generateHMACSignature(secret, stringToSign string) (string, error) {
	decodedSecret, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to decode secret: %w", err)
	}

	h := hmac.New(sha256.New, decodedSecret)
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return signature, nil
}

// verifyMatch sends a request to the Azure App Configuration REST API to verify the provided credentials
// https://learn.microsoft.com/en-us/azure/azure-app-configuration/rest-api-authentication-hmac
func (s Scanner) verifyMatch(ctx context.Context, client *http.Client, endpoint, id, secret string) (bool, error) {
	apiVersion := "1.0"
	requestPath := "/kv"
	query := fmt.Sprintf("?api-version=%s", apiVersion)
	url := fmt.Sprintf("%s%s%s", endpoint, requestPath, query)

	// Prepare request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	// Set required headers
	host := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	date := time.Now().UTC().Format(http.TimeFormat)
	contentHash := base64.StdEncoding.EncodeToString(sha256.New().Sum(nil)) // SHA256 hash of an empty body

	req.Header.Set("Host", host)
	req.Header.Set("Date", date)
	req.Header.Set("x-ms-content-sha256", contentHash)

	// Create the string to sign
	stringToSign := fmt.Sprintf("%s\n%s%s\n%s;%s;%s",
		http.MethodGet,
		requestPath,
		query,
		date,
		host,
		contentHash,
	)

	// Generate the HMAC signature
	signature, err := generateHMACSignature(secret, stringToSign)
	if err != nil {
		return false, fmt.Errorf("failed to generate HMAC signature: %w", err)
	}

	// Set the Authorization header
	authorizationHeader := fmt.Sprintf(
		"HMAC-SHA256 Credential=%s&SignedHeaders=date;host;x-ms-content-sha256&Signature=%s",
		id,
		signature,
	)
	req.Header.Set("Authorization", authorizationHeader)

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check the response status
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("got unexpected status code: %d", resp.StatusCode)
	}
}
