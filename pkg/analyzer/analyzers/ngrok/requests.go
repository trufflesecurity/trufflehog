package ngrok

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
)

const (
	ngrokAPIBaseURL           = "https://api.ngrok.com"
	reservedAddressesEndpoint = "/reserved_addrs"
	domainsEndpoint           = "/reserved_domains"
	endpointsEndpoint         = "/endpoints"
	apiKeysEndpoint           = "/api_keys"
	sshCredentialsEndpoint    = "/ssh_credentials"
	authtokensEndpoint        = "/credentials"
	botUsersEndpoint          = "/bot_users"
)

func determineAccountType(client *http.Client, info *secretInfo, key string) error {
	// To determine if the account is free or paid, we can attempt to create a reserved address
	// Reserved Addresses are only available to paid accounts, so if the response contains the
	// error "ERR_NGROK_501", we can assume the account is on a free plan.
	// Ref: https://ngrok.com/docs/errors/err_ngrok_501

	const errorCodeFreeAccount = "ERR_NGROK_501"

	url := fmt.Sprintf("%s%s", ngrokAPIBaseURL, reservedAddressesEndpoint)
	body, statusCode, err := makeAPIRequest(client, http.MethodPost, url, key)
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
	url := fmt.Sprintf("%s%s", ngrokAPIBaseURL, endpointsEndpoint)
	info.Endpoints = []endpoint{}
	for {
		res, err := fetchResources(client, url, key)
		if err != nil {
			return err
		}
		info.Endpoints = append(info.Endpoints, res.Endpoints...)
		url = res.NextPageURI
		if url == "" {
			break
		}
	}
	return nil
}

func populateAPIKeys(client *http.Client, info *secretInfo, key string) error {
	url := fmt.Sprintf("%s%s", ngrokAPIBaseURL, apiKeysEndpoint)
	info.APIKeys = []apiKey{}
	for {
		res, err := fetchResources(client, url, key)
		if err != nil {
			return err
		}
		info.APIKeys = append(info.APIKeys, res.APIKeys...)
		url = res.NextPageURI
		if url == "" {
			break
		}
	}
	return nil
}

func populateSSHCredentials(client *http.Client, info *secretInfo, key string) error {
	url := fmt.Sprintf("%s%s", ngrokAPIBaseURL, sshCredentialsEndpoint)
	info.SSHCredentials = []sshCredential{}
	for {
		res, err := fetchResources(client, url, key)
		if err != nil {
			return err
		}
		info.SSHCredentials = append(info.SSHCredentials, res.SSHCredentials...)
		url = res.NextPageURI
		if url == "" {
			break
		}
	}
	return nil
}

func populateAuthtokens(client *http.Client, info *secretInfo, key string) error {
	url := fmt.Sprintf("%s%s", ngrokAPIBaseURL, authtokensEndpoint)
	info.Authtokens = []authtoken{}
	for {
		res, err := fetchResources(client, url, key)
		if err != nil {
			return err
		}
		info.Authtokens = append(info.Authtokens, res.Authtokens...)
		url = res.NextPageURI
		if url == "" {
			break
		}
	}
	return nil
}

func populateDomains(client *http.Client, info *secretInfo, key string) error {
	url := fmt.Sprintf("%s%s", ngrokAPIBaseURL, domainsEndpoint)
	info.Domains = []domain{}
	for {
		res, err := fetchResources(client, url, key)
		if err != nil {
			return err
		}
		info.Domains = append(info.Domains, res.Domains...)
		url = res.NextPageURI
		if url == "" {
			break
		}
	}
	return nil
}

func populateBotUsers(client *http.Client, info *secretInfo, key string) error {
	url := fmt.Sprintf("%s%s", ngrokAPIBaseURL, botUsersEndpoint)
	info.BotUsers = []botUser{}
	for {
		res, err := fetchResources(client, url, key)
		if err != nil {
			return err
		}
		info.BotUsers = append(info.BotUsers, res.BotUsers...)
		url = res.NextPageURI
		if url == "" {
			break
		}
	}
	return nil
}

func fetchResources(client *http.Client, url string, key string) (*paginatedResponse, error) {
	for {
		body, status, err := makeAPIRequest(client, http.MethodGet, url, key)
		if err != nil {
			return nil, err
		}
		switch status {
		case http.StatusOK:
			var resource paginatedResponse
			if err := json.Unmarshal(body, &resource); err != nil {
				return nil, err
			}
			return &resource, nil
		case http.StatusForbidden:
			return nil, fmt.Errorf("invalid API key or access forbidden: %s", body)
		default:
			return nil, fmt.Errorf("unexpected status code: %d", status)
		}
	}
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

func makeAPIRequest(client *http.Client, method string, url string, key string) ([]byte, int, error) {
	var reqBody io.Reader = nil
	if method == http.MethodPost {
		reqBody = strings.NewReader("{}")
	}
	req, err := http.NewRequest(method, url, reqBody)
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

// Functions to create analyzers.Resource objects for different resource types

func createEndpointResource(endpoint endpoint) analyzers.Resource {
	return analyzers.Resource{
		Name:               endpoint.ID,
		FullyQualifiedName: "endpoint/" + endpoint.ID,
		Type:               "endpoint",
		Metadata: map[string]any{
			"region":    endpoint.Region,
			"host":      endpoint.Host,
			"port":      endpoint.Port,
			"publicURL": endpoint.PublicURL,
			"proto":     endpoint.Proto,
			"hostport":  endpoint.Hostport,
			"type":      endpoint.Type,
			"uri":       endpoint.URI,
			"bindings":  endpoint.Bindings,
			"metadata":  endpoint.Metadata,
			"createdAt": endpoint.CreatedAt,
			"updatedAt": endpoint.UpdatedAt,
		},
	}
}

func createDomainResource(domain domain) analyzers.Resource {
	return analyzers.Resource{
		Name:               domain.ID,
		FullyQualifiedName: "domain/" + domain.ID,
		Type:               "domain",
		Metadata: map[string]any{
			"uri":       domain.URI,
			"domain":    domain.Domain,
			"metadata":  domain.Metadata,
			"createdAt": domain.CreatedAt,
		},
	}
}

func createAPIKeyResource(apiKey apiKey) analyzers.Resource {
	return analyzers.Resource{
		Name:               apiKey.ID,
		FullyQualifiedName: "api_key/" + apiKey.ID,
		Type:               "api_key",
		Metadata: map[string]any{
			"uri":         apiKey.URI,
			"description": apiKey.Description,
			"metadata":    apiKey.Metadata,
			"ownerID":     apiKey.OwnerID,
			"createdAt":   apiKey.CreatedAt,
		},
	}
}
func createSSHKeyResource(sshCredential sshCredential) analyzers.Resource {
	return analyzers.Resource{
		Name:               sshCredential.ID,
		FullyQualifiedName: "ssh_credential/" + sshCredential.ID,
		Type:               "ssh_credential",
		Metadata: map[string]any{
			"uri":         sshCredential.URI,
			"description": sshCredential.Description,
			"publicKey":   sshCredential.PublicKey,
			"metadata":    sshCredential.Metadata,
			"acl":         sshCredential.ACL,
			"ownerID":     sshCredential.OwnerID,
			"createdAt":   sshCredential.CreatedAt,
		},
	}
}

func createAuthtokenResource(authtoken authtoken) analyzers.Resource {
	return analyzers.Resource{
		Name:               authtoken.ID,
		FullyQualifiedName: "authtoken/" + authtoken.ID,
		Type:               "authtoken",
		Metadata: map[string]any{
			"uri":         authtoken.URI,
			"description": authtoken.Description,
			"metadata":    authtoken.Metadata,
			"acl":         authtoken.ACL,
			"ownerID":     authtoken.OwnerID,
			"createdAt":   authtoken.CreatedAt,
		},
	}
}

func createBotUserResource(botUser botUser) analyzers.Resource {
	return analyzers.Resource{
		Name:               botUser.ID,
		FullyQualifiedName: "bot_user/" + botUser.ID,
		Type:               "bot_user",
		Metadata: map[string]any{
			"uri":       botUser.URI,
			"name":      botUser.Name,
			"active":    botUser.Active,
			"createdAt": botUser.CreatedAt,
		},
	}
}

func createUserResource(user user) analyzers.Resource {
	return analyzers.Resource{
		Name:               user.ID,
		FullyQualifiedName: "user/" + user.ID,
		Type:               "user",
	}
}
