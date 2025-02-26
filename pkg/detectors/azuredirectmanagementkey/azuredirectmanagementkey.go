package azuredirectmanagementkey

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
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

const RFC3339WithoutMicroseconds = "2006-01-02T15:04:05"

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	urlPat        = regexp.MustCompile(`https://([a-z0-9][a-z0-9-]{0,48}[a-z0-9])\.management\.azure-api\.net`)         // https://azure.github.io/PSRule.Rules.Azure/en/rules/Azure.APIM.Name/
	primaryKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"azure"}) + `\b([a-zA-Z0-9+\/-]{86,88}\b={0,2})`) // Base64-encoded primary key
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{".management.azure-api.net"}
}

// FromData will find and optionally verify Azure Management API keys in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	urlMatchesUnique := make(map[string]string)
	for _, urlMatch := range urlPat.FindAllStringSubmatch(dataStr, -1) {
		urlMatchesUnique[urlMatch[0]] = urlMatch[1] // urlMatch[0] is the full url, urlMatch[1] is the service name
	}
	primaryKeyMatchesUnique := make(map[string]struct{})
	for _, keyMatch := range primaryKeyPat.FindAllStringSubmatch(dataStr, -1) {
		primaryKeyMatchesUnique[strings.TrimSpace(keyMatch[1])] = struct{}{}
	}

	for baseUrl, serviceName := range urlMatchesUnique {
		for primaryKey := range primaryKeyMatchesUnique {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AzureDirectManagementKey,
				Raw:          []byte(baseUrl),
				RawV2:        []byte(baseUrl + primaryKey),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := s.verifyMatch(ctx, client, baseUrl, serviceName, primaryKey)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, primaryKey)
			}

			results = append(results, s1)
			if s1.Verified {
				break
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureDirectManagementKey
}

func (s Scanner) Description() string {
	return "Azure API Management provides a direct management REST API for performing operations on selected entities, such as users, groups, products, and subscriptions."
}

func (s Scanner) verifyMatch(ctx context.Context, client *http.Client, baseUrl, serviceName, key string) (bool, error) {
	url := fmt.Sprintf(
		"%s/subscriptions/default/resourceGroups/default/providers/Microsoft.ApiManagement/service/%s/apis?api-version=2024-05-01",
		baseUrl, serviceName,
	)
	accessToken, err := generateAccessToken(key)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("SharedAccessSignature %s", accessToken))
	resp, err := client.Do(req)
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

// https://learn.microsoft.com/en-us/rest/api/apimanagement/apimanagementrest/azure-api-management-rest-api-authentication
func generateAccessToken(key string) (string, error) {
	expiry := time.Now().UTC().Add(5 * time.Second).Format(RFC3339WithoutMicroseconds) // expires in 5 seconds
	expiry = expiry + ".0000000Z"                                                      // 7 decimals microsecond's precision is must for access token

	// Construct the string-to-sign
	stringToSign := fmt.Sprintf("integration\n%s", expiry)

	// Generate HMAC-SHA512 signature
	h := hmac.New(sha512.New, []byte(key))
	h.Write([]byte(stringToSign))
	signature := h.Sum(nil)

	// Base64 encode the signature
	encodedSignature := base64.StdEncoding.EncodeToString(signature)

	// Create the access token
	accessToken := fmt.Sprintf("uid=integration&ex=%s&sn=%s", expiry, encodedSignature)
	return accessToken, nil
}
