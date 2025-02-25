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

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	urlPat = regexp.MustCompile(`https://([a-zA-Z0-9-]{0,50})\.management\.azure-api\.net`) // https://azure.github.io/PSRule.Rules.Azure/en/rules/Azure.APIM.Name/
	keyPat = regexp.MustCompile(`([a-zA-Z0-9+\/-]{86,88}={0,2})`)                           // Base64-encoded key
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{".management.azure-api.net"}
}

// FromData will find and optionally verify Azure Management API keys in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	urlMatches := urlPat.FindAllStringSubmatch(dataStr, -1)
	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, urlMatch := range urlMatches {
		serviceName := urlMatch[1]
		for _, keyMatch := range keyMatches {
			resMatch := strings.TrimSpace(keyMatch[0])
			url := fmt.Sprintf(
				"%s/subscriptions/default/resourceGroups/default/providers/Microsoft.ApiManagement/service/%s/apis?api-version=2024-05-01",
				urlMatch[0], serviceName,
			)
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AzureDirectManagementKey,
				Raw:          []byte(urlMatch[0]),
				RawV2:        []byte(urlMatch[0] + resMatch),
				Redacted:     url,
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				expiry := time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
				expiry = expiry[:27] + "Z" // 7 decimals precision for miliseconds
				accessToken, err := generateAccessToken(resMatch, expiry)
				if err != nil {
					continue
				}
				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", fmt.Sprintf("SharedAccessSignature %s", accessToken))
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					s1.Verified = true
				}

			}

			results = append(results, s1)
			if s1.Verified {
				break
			}
		}
	}

	return results, nil
}

func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureDirectManagementKey
}

func (s Scanner) Description() string {
	return "The Azure Management API is a RESTful interface for managing Azure resources programmatically through Azure Resource Manager (ARM), supporting automation with tools like Azure CLI and PowerShell. An Azure Management Direct Access API Key enables secure, non-interactive authentication, allowing direct access to manage resources via Azure Active Directory (AAD)."
}

// https://learn.microsoft.com/en-us/rest/api/apimanagement/apimanagementrest/azure-api-management-rest-api-authentication
func generateAccessToken(key, expiry string) (string, error) {
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
