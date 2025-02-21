package launchdarkly

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

var (
	//go:embed api_endpoints.json
	apiEndpointsConfig []byte

	baseURL = "https://app.launchdarkly.com/api"

	endpoints = map[string]string{
		"callerIdentity": "/v2/caller-identity",
		"getToken":       "/api/v2/tokens/%s",
	}
)

// API is a launchdarkly API details
type API struct {
	Name               string `json:"name"`
	Endpoint           string `json:"endpoint"`
	ValidStatusCode    int    `json:"valid_status_code"`
	InvalidStatusCodes []int  `json:"invalid_status_codes"`
	Permission         string `json:"permission"`
}

// callerIdentityResponse is /v2/caller-identity API response
type callerIdentityResponse struct {
	AccountID    string `json:"accountId"`
	TokenName    string `json:"tokenName"`
	TokenID      string `json:"tokenId"`
	MemberID     string `json:"memberId"`
	ServiceToken bool   `json:"serviceToken"`
}

// readAPIEndpontsConfig read embedded api endpoint details
func readAPIEndpontsConfig() ([]API, error) {
	var apis []API
	if err := json.Unmarshal(apiEndpointsConfig, &apis); err != nil {
		return nil, err
	}

	return apis, nil
}

// makeLaunchDarklyRequest send the HTTP GET API request to passed url with passed token and return response body and status code
func makeLaunchDarklyRequest(client *http.Client, endpoint, token string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(http.MethodGet, baseURL+endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}

	// add required keys in the header
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	responseBodyByte, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	return responseBodyByte, resp.StatusCode, nil
}

func statusContains(status int, list ...int) bool {
	for _, v := range list {
		if status == v {
			return true
		}
	}

	return false
}

func callAPIs(client *http.Client, token string, secretInfo *SecretInfo) error {
	apis, err := readAPIEndpontsConfig()
	if err != nil {
		return err
	}

	for _, api := range apis {
		if err := apiRequest(client, api.Endpoint, token, api.Permission, api.ValidStatusCode, api.InvalidStatusCodes); err != nil {
			return err
		}
	}
}

func apiRequest(client *http.Client, endpoint, token, permission string, validStatusCode int, invalidStatusCodes []int) error {
	response, statusCode, err := makeLaunchDarklyRequest(client, endpoint, token)
	if err != nil {
		return err
	}

	switch {
	case statusContains(statusCode, validStatusCode):
		// handle response
		return nil
	case statusContains(statusCode, invalidStatusCodes...):
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d for endpoint: %s", statusCode, endpoint)
	}
}

// callerIdentity calls the /v2/caller-identity and /v2/tokens/<id> APIs with provided token and prepare caller identity
func callerIdentity(client *http.Client, token string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeLaunchDarklyRequest(client, "/v2/caller-identity", token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var caller callerIdentityResponse

		if err := json.Unmarshal(response, &caller); err != nil {
			return err
		}

		// get token details from /v2/tokens/<id> API
		response, statusCode, err := makeLaunchDarklyRequest(client, "/api/v2/tokens/"+caller.TokenID, token)
		if err != nil {
			return err
		}
	}

	return nil
}
