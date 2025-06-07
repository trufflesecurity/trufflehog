package azure_cosmosdb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func verifyCosmosTableDB(client *http.Client, accountUrl, key string) (bool, error) {
	// decode the base64 encoded key
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return false, fmt.Errorf("failed to decode key: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s:443/Tables", accountUrl), nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %v", err)
	}

	// extract abc123 from abc123.table.cosmos.azure.com
	accountName := strings.TrimPrefix(accountUrl, ".table.cosmos.azure.com")

	dateRFC1123 := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	authHeader := fmt.Sprintf("SharedKeyLite %s:%s", accountName, createTablesSignature(decodedKey, accountName, dateRFC1123))

	// required headers
	// docs: https://learn.microsoft.com/en-us/rest/api/cosmos-db/common-cosmosdb-rest-request-headers
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("x-ms-date", dateRFC1123)
	req.Header.Set("x-ms-version", "2019-02-02")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// lookup foo.table.cosmos.azure.com: no such host
		if strings.Contains(err.Error(), "no such host") {
			return false, errNoHost
		}

		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// Check response status code
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func createTablesSignature(decodedKey []byte, accountName, dateRFC1123 string) string {
	// create string to sign (method + date)
	stringToSign := fmt.Sprintf("%s\n%s", dateRFC1123, fmt.Sprintf("/%s/Tables", accountName))

	// Compute HMAC-SHA256 signature
	h := hmac.New(sha256.New, decodedKey)
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return signature
}
