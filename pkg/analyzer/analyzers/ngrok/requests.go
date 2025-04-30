package ngrok

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func determineAccountType(client *http.Client, info *secretInfo, key string) error {
	// To determine if the account is free or paid, we can attempt to create a reserved address
	// Reserved Addresses are only available to paid accounts, so if the response contains the
	// error "ERR_NGROK_501", we can assume the account is on a free plan.
	// Ref: https://ngrok.com/docs/errors/err_ngrok_501

	const errorCodeFreeAccount = "ERR_NGROK_501"

	body, statusCode, err := callNgrokAPIEndpoint(client, http.MethodPost, "/reserved_addrs", key)
	if err != nil {
		return err
	}

	// The response should be a 400 Bad Request based on our request. Any other status code indicates an error.
	if statusCode != http.StatusBadRequest {
		return fmt.Errorf("unexpected status code: %d while determining account type", statusCode)
	}

	switch statusCode {
	case http.StatusBadRequest:
		if strings.Contains(string(body), errorCodeFreeAccount) {
			info.AccountType = AccountFree
		} else {
			info.AccountType = AccountPaid
		}
	case http.StatusForbidden:
		return fmt.Errorf("invalid API key or access forbidden: %s", body)
	default:
		return fmt.Errorf("unexpected status code: %d while determining account type", statusCode)
	}

	return nil
}

func populateAllResources(client *http.Client, info *secretInfo, key string) error {
	// Fetch all resources and populate the secretInfo struct with the data
	// This is a placeholder function. The actual implementation will depend on the API endpoints and response formats.
	// For example, you might want to call different endpoints to fetch API keys, SSH keys, etc.

	// Example of populating API keys
	if err := populateEndpoints(client, info, key); err != nil {
		return err
	}
	if err := populateDomains(client, info, key); err != nil {
		return err
	}
	if err := populateAPIKeys(client, info, key); err != nil {
		return err
	}
	if err := populateAuthtokens(client, info, key); err != nil {
		return err
	}
	if err := populateSSHCredentials(client, info, key); err != nil {
		return err
	}
	if err := populateBotUsers(client, info, key); err != nil {
		return err
	}
	populateUsers(info)

	return nil
}

func populateEndpoints(client *http.Client, info *secretInfo, key string) error {
	res := endpointResponse{}
	if err := populateNgrokResource(client, &res, "/endpoints", key); err != nil {
		return err
	}
	info.Endpoints = res.Endpoints
	return nil
}

func populateAPIKeys(client *http.Client, info *secretInfo, key string) error {
	res := apiKeyResponse{}
	if err := populateNgrokResource(client, &res, "/api_keys", key); err != nil {
		return err
	}
	info.APIKeys = res.APIKeys
	return nil
}

func populateSSHCredentials(client *http.Client, info *secretInfo, key string) error {
	res := sshCredentialResponse{}
	if err := populateNgrokResource(client, &res, "/ssh_credentials", key); err != nil {
		return err
	}
	info.SSHCredentials = res.SSHCredentials
	return nil
}

func populateAuthtokens(client *http.Client, info *secretInfo, key string) error {
	res := authtokenResponse{}
	if err := populateNgrokResource(client, &res, "/credentials", key); err != nil {
		return err
	}
	info.Authtokens = res.Authtokens
	return nil
}

func populateDomains(client *http.Client, info *secretInfo, key string) error {
	res := domainResponse{}
	if err := populateNgrokResource(client, &res, "/reserved_domains", key); err != nil {
		return err
	}
	info.Domains = res.Domains
	return nil
}

func populateBotUsers(client *http.Client, info *secretInfo, key string) error {
	res := botUserResponse{}
	if err := populateNgrokResource(client, &res, "/bot_users", key); err != nil {
		return err
	}
	info.BotUsers = res.BotUsers
	return nil
}

func populateNgrokResource(client *http.Client, targetResource any, endpoint string, key string) error {
	body, status, err := callNgrokAPIEndpoint(client, http.MethodGet, endpoint+"?limit=5", key)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK:
		if err := json.Unmarshal(body, &targetResource); err != nil {
			return err
		}
	case http.StatusForbidden:
		return fmt.Errorf("invalid API key or access forbidden: %s", body)
	default:
		return fmt.Errorf("unexpected status code: %d", status)
	}
	return nil
}

func populateUsers(info *secretInfo) {
	// Creating a map to track unique user IDs to help in avoiding
	// duplicates when adding users to the info.Users slice
	uniqueUserIDs := map[string]bool{}

	processOwnerID := func(ownerID string) {
		if strings.HasPrefix(ownerID, "usr_") {
			if uniqueUserIDs[ownerID] {
				return
			}
			uniqueUserIDs[ownerID] = true
			info.Users = append(info.Users, user{ID: ownerID})
		}
	}

	for _, token := range info.Authtokens {
		processOwnerID(token.OwnerID)
	}

	for _, sshKey := range info.SSHCredentials {
		processOwnerID(sshKey.OwnerID)
	}

	for _, apiKey := range info.APIKeys {
		processOwnerID(apiKey.OwnerID)
	}
}

func callNgrokAPIEndpoint(client *http.Client, method string, endpoint string, key string) ([]byte, int, error) {
	var reqBody io.Reader = nil
	if method == http.MethodPost {
		reqBody = strings.NewReader("{}")
	}
	req, err := http.NewRequest(method, ngrokAPIBaseURL+endpoint, reqBody)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Ngrok-Version", "2")
	res, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read response body: %w", err)
	}

	return bodyBytes, res.StatusCode, nil
}
