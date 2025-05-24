package coinbase

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	requestHostProductAPI = "api.coinbase.com"
	requestHostCDPAPI     = "api.cdp.coinbase.com"
)

// Coinbase API requires the credentials encoded in a JWT token
// The JWT token is signed with the private key and expires in 2 minutes
func buildJWT(method, host, endpoint, keyName, key string) (string, error) {
	// Decode the PEM key
	pemStr := strings.ReplaceAll(key, `\n`, "\n")
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return "", fmt.Errorf("failed to decode PEM block containing EC private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse EC private key: %v", err)
	}

	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"sub": keyName,
		"iss": "cdp",
		"nbf": now,
		"exp": now + 120,
		"uri": fmt.Sprintf("%s %s%s", method, host, endpoint),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keyName
	token.Header["nonce"] = fmt.Sprintf("%x", makeNonce())

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %v", err)
	}

	return signedToken, nil
}

func makeNonce() []byte {
	nonce := make([]byte, 16) // 128-bit nonce
	_, _ = rand.Read(nonce)
	return nonce
}

func makeAPIRequest(client *http.Client, method, uri, jwtToken string) ([]byte, error) {
	req, err := http.NewRequest(method, uri, http.NoBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	statusCode := res.StatusCode

	switch statusCode {
	case http.StatusOK:
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}
		return body, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("invalid credentials %d", statusCode)
	default:
		return nil, fmt.Errorf("unexpected status code %d", statusCode)
	}
}

func testAllPermissions(client *http.Client, info *secretInfo, keyName, key string) error {
	permissionEndpoint := "/api/v3/brokerage/key_permissions"
	jwt, err := buildJWT(http.MethodGet, requestHostProductAPI, permissionEndpoint, keyName, key)
	if err != nil {
		return err
	}
	uri := fmt.Sprintf("https://%s%s", requestHostProductAPI, permissionEndpoint)
	body, err := makeAPIRequest(client, http.MethodGet, uri, jwt)
	if err != nil {
		return err
	}
	var permissionsResponse keyPermissionsResponse
	if err := json.Unmarshal(body, &permissionsResponse); err != nil {
		return fmt.Errorf("failed to unmarshal permissions response: %w", err)
	}
	if permissionsResponse.CanView {
		info.addPermission(View)
	}
	if permissionsResponse.CanTrade {
		info.addPermission(Trade)
	}
	if permissionsResponse.CanTransfer {
		info.addPermission(Transfer)
	}

	return nil
}

func populateResources(client *http.Client, info *secretInfo, keyName, key string) error {
	if err := populateAccounts(client, info, keyName, key); err != nil {
		return err
	}
	if err := populateOrders(client, info, keyName, key); err != nil {
		return err
	}
	if err := populatePortfolios(client, info, keyName, key); err != nil {
		return err
	}
	if err := populatePaymentMethods(client, info, keyName, key); err != nil {
		return err
	}
	if err := populateWallets(client, info, keyName, key); err != nil {
		return err
	}
	if err := populateAddresses(client, info, keyName, key); err != nil {
		return err
	}

	return nil
}

func populateAccounts(client *http.Client, info *secretInfo, keyName, key string) error {
	limit := 250
	maxPageLimit := 25 // Safety: stop after 25 pages
	endpoint := "/api/v3/brokerage/accounts"
	uri := fmt.Sprintf("https://%s%s", requestHostProductAPI, endpoint)
	params := fmt.Sprintf("?limit=%d", limit)

	jwt, err := buildJWT(http.MethodGet, requestHostProductAPI, endpoint, keyName, key)
	if err != nil {
		return err
	}
	for i := 0; i < maxPageLimit; i++ {
		body, err := makeAPIRequest(client, http.MethodGet, uri+params, jwt)
		if err != nil {
			return err
		}
		var accountsResponse accountsResponse
		if err := json.Unmarshal(body, &accountsResponse); err != nil {
			return fmt.Errorf("failed to unmarshal accounts response: %w", err)
		}
		info.Accounts = append(info.Accounts, accountsResponse.Accounts...)
		if accountsResponse.HasNext {
			uri = fmt.Sprintf("?limit=%d&cursor=%s", limit, accountsResponse.Cursor)
		} else {
			break
		}
	}

	return nil
}

func populateOrders(client *http.Client, info *secretInfo, keyName, key string) error {
	limit := 100
	maxPageLimit := 25
	endpoint := "/api/v3/brokerage/orders/historical/batch"
	uri := fmt.Sprintf("https://%s%s", requestHostProductAPI, endpoint)
	params := fmt.Sprintf("?limit=%d", limit)

	jwt, err := buildJWT(http.MethodGet, requestHostProductAPI, endpoint, keyName, key)
	if err != nil {
		return err
	}
	for i := 0; i < maxPageLimit; i++ {
		body, err := makeAPIRequest(client, http.MethodGet, uri+params, jwt)
		if err != nil {
			return err
		}
		var ordersResponse ordersResponse
		if err := json.Unmarshal(body, &ordersResponse); err != nil {
			return fmt.Errorf("failed to unmarshal orders response: %w", err)
		}
		info.Orders = append(info.Orders, ordersResponse.Orders...)
		if ordersResponse.HasNext {
			endpoint = fmt.Sprintf("?limit=%d&cursor=%s", limit, ordersResponse.Cursor)
		} else {
			break
		}
	}

	return nil
}

func populatePaymentMethods(client *http.Client, info *secretInfo, keyName, key string) error {
	endpoint := "/api/v3/brokerage/payment_methods"
	uri := fmt.Sprintf("https://%s%s", requestHostProductAPI, endpoint)
	jwt, err := buildJWT(http.MethodGet, requestHostProductAPI, endpoint, keyName, key)
	if err != nil {
		return err
	}
	body, err := makeAPIRequest(client, http.MethodGet, uri, jwt)
	if err != nil {
		return err
	}
	var paymentMethodsResponse paymentMethodsResponse
	if err := json.Unmarshal(body, &paymentMethodsResponse); err != nil {
		return fmt.Errorf("failed to unmarshal payment methods response: %w", err)
	}
	info.PaymentMethods = paymentMethodsResponse.PaymentMethods

	return nil
}

func populatePortfolios(client *http.Client, info *secretInfo, keyName, key string) error {
	endpoint := "/api/v3/brokerage/portfolios"
	uri := fmt.Sprintf("https://%s%s", requestHostProductAPI, endpoint)
	jwt, err := buildJWT(http.MethodGet, requestHostProductAPI, endpoint, keyName, key)
	if err != nil {
		return err
	}
	body, err := makeAPIRequest(client, http.MethodGet, uri, jwt)
	if err != nil {
		return err
	}
	var portfoliosResponse portfoliosResponse
	if err := json.Unmarshal(body, &portfoliosResponse); err != nil {
		return fmt.Errorf("failed to unmarshal portfolios response: %w", err)
	}
	info.Portfolios = portfoliosResponse.Portfolios

	return nil
}

func populateWallets(client *http.Client, info *secretInfo, keyID, secret string) error {
	limit := 100
	maxPageLimit := 25
	endpoint := "/platform/v1/wallets"
	uri := fmt.Sprintf("https://%s%s", requestHostCDPAPI, endpoint)
	params := fmt.Sprintf("?limit=%d", limit)
	jwt, err := buildJWT(http.MethodGet, requestHostCDPAPI, endpoint, keyID, secret)
	if err != nil {
		return err
	}
	for i := 0; i < maxPageLimit; i++ {
		body, err := makeAPIRequest(client, http.MethodGet, uri+params, jwt)
		if err != nil {
			return err
		}
		var walletssResponse walletsResponse
		if err := json.Unmarshal(body, &walletssResponse); err != nil {
			return fmt.Errorf("failed to unmarshal wallets response: %w", err)
		}
		info.Wallets = append(info.Wallets, walletssResponse.Data...)
		if walletssResponse.HasMore {
			uri = fmt.Sprintf("?limit=%d&page=%s", limit, walletssResponse.NextPage)
		} else {
			break
		}
	}

	return nil
}

func populateAddresses(client *http.Client, info *secretInfo, keyID, secret string) error {
	limit := 100
	maxPageLimit := 25
	for _, wallet := range info.Wallets {
		endpoint := fmt.Sprintf("/platform/v1/wallets/%s/addresses", wallet.ID)
		uri := fmt.Sprintf("https://%s%s", requestHostCDPAPI, endpoint)
		params := fmt.Sprintf("?limit=%d", limit)
		jwt, err := buildJWT(http.MethodGet, requestHostCDPAPI, endpoint, keyID, secret)
		if err != nil {
			return err
		}
		for i := 0; i < maxPageLimit; i++ {
			body, err := makeAPIRequest(client, http.MethodGet, uri+params, jwt)
			if err != nil {
				return err
			}
			var addressesResponse addressesResponse
			if err := json.Unmarshal(body, &addressesResponse); err != nil {
				return fmt.Errorf("failed to unmarshal addresses response: %w", err)
			}
			info.Addresses = append(info.Addresses, addressesResponse.Data...)
			if addressesResponse.HasMore {
				uri = fmt.Sprintf("?limit=%d&page=%s", limit, addressesResponse.NextPage)
			} else {
				break
			}
		}
	}

	return nil
}
