package fastly

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
)

type endpoint int

const (
	// list of endpoints
	selfToken endpoint = iota
	currentUser
	userTokens
	automationTokens
	service
	serviceVersions
	serviceVersionACLs
	serviceVersionDictionary
	serviceVersionBackend
)

var (
	baseURL = "https://api.fastly.com"

	// endpoints contain Fastly API endpoints
	endpoints = map[endpoint]string{
		selfToken:                "/tokens/self",
		currentUser:              "/current_user",
		userTokens:               "/tokens",
		automationTokens:         "/automation-tokens",
		service:                  "/service",
		serviceVersions:          "/service/%s/version",               // require service id
		serviceVersionACLs:       "/service/%s/version/%s/acl",        // require service id and version number
		serviceVersionDictionary: "/service/%s/version/%s/dictionary", // require service id and version number
		serviceVersionBackend:    "/service/%s/version/%s/backend",    // require service id and version number
	}
)

// makeFastlyRequest send the API request to passed url with passed key as API Key and return response body and status code
func makeFastlyRequest(client *http.Client, endpoint, key string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(http.MethodGet, baseURL+endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}

	// add key in the header
	req.Header.Add("Fastly-Key", key)

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

// captureResources try to capture all the resource that the key can access
func captureResources(client *http.Client, key string, secretInfo *SecretInfo) error {
	var (
		wg             sync.WaitGroup
		errAggWg       sync.WaitGroup
		aggregatedErrs = make([]error, 0)
		errChan        = make(chan error, 1)
	)

	errAggWg.Add(1)
	go func() {
		defer errAggWg.Done()
		for err := range errChan {
			aggregatedErrs = append(aggregatedErrs, err)
		}
	}()

	// helper to launch tasks concurrently.
	launchTask := func(task func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := task(); err != nil {
				errChan <- err
			}
		}()
	}

	launchTask(func() error { return captureAutomationTokens(client, key, secretInfo) })
	launchTask(func() error { return captureUserTokens(client, key, secretInfo) })

	// capture services and their sub resources
	launchTask(func() error {
		if err := captureServices(client, key, secretInfo); err != nil {
			return err
		}

		services := secretInfo.listResourceByType(TypeService)
		for _, service := range services {
			if err := captureSvcVersions(client, key, service, secretInfo); err != nil {
				return err
			}
		}

		// capture each version sub resources
		versions := secretInfo.listResourceByType(TypeSvcVersion)
		for _, version := range versions {
			launchTask(func() error { return captureSvcVersionACLs(client, key, version, secretInfo) })
			launchTask(func() error { return captureSvcVersionDicts(client, key, version, secretInfo) })
			launchTask(func() error { return captureSvcVersionBackends(client, key, version, secretInfo) })
		}

		return nil
	})

	wg.Wait()
	close(errChan)
	errAggWg.Wait()

	if len(aggregatedErrs) > 0 {
		return errors.Join(aggregatedErrs...)
	}

	return nil
}

// captureTokenInfo calls `/tokens/self` API and capture the token information in secretInfo
func captureTokenInfo(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, endpoints[selfToken], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var token SelfToken

		if err := json.Unmarshal(respBody, &token); err != nil {
			return err
		}

		if token.ExpiresAt == "" {
			token.ExpiresAt = "never"
		}

		secretInfo.TokenInfo = token

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired api key")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, endpoints[selfToken])
	}
}

// captureUserInfo calls `/current_user` API and capture the current user information in secretInfo
func captureUserInfo(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, endpoints[currentUser], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var user User

		if err := json.Unmarshal(respBody, &user); err != nil {
			return err
		}

		secretInfo.UserInfo = user

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, endpoints[currentUser])
	}
}

// captureUserTokens calls `/tokens` API
func captureUserTokens(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, endpoints[userTokens], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var tokens []Token

		if err := json.Unmarshal(respBody, &tokens); err != nil {
			return err
		}

		for _, token := range tokens {
			resource := FastlyResource{
				ID:   token.ID,
				Name: token.Name,
				Type: TypeUserToken,
				Metadata: map[string]string{
					"Scope":      token.Scope,
					"Role":       token.Role,
					"Expires At": token.ExpiresAt,
				},
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// captureAutomationTokens calls `/automation-tokens` API
func captureAutomationTokens(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, endpoints[automationTokens], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var tokens TokenData

		if err := json.Unmarshal(respBody, &tokens); err != nil {
			return err
		}

		for _, token := range tokens.Data {
			resource := FastlyResource{
				ID:   token.ID,
				Name: token.Name,
				Type: TypeAutomationToken,
				Metadata: map[string]string{
					"Scope":      token.Scope,
					"Role":       token.Role,
					"Expires At": token.ExpiresAt,
				},
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// captureServices calls `/service` API
func captureServices(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, endpoints[service], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var services []Service

		if err := json.Unmarshal(respBody, &services); err != nil {
			return err
		}

		for _, service := range services {
			resource := FastlyResource{
				ID:   service.ID,
				Name: service.Name,
				Type: TypeService,
				Metadata: map[string]string{
					"Service Type": service.Type,
				},
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, endpoints[service])
	}
}

// captureSvcVersions calls `/service/<id>/version` API
func captureSvcVersions(client *http.Client, key string, parentService FastlyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, fmt.Sprintf(endpoints[serviceVersions], parentService.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var versions []Version

		if err := json.Unmarshal(respBody, &versions); err != nil {
			return err
		}

		for _, version := range versions {
			resource := FastlyResource{
				ID:       strconv.Itoa(version.Number),
				Name:     parentService.ID + "/version/" + strconv.Itoa(version.Number), // versions has no specific name
				Type:     TypeSvcVersion,
				Metadata: map[string]string{"service_id": version.ServiceID},
				Parent:   &parentService,
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// captureSvcVersionACLs calls `/service/<id>/version/<number>/acl` API
func captureSvcVersionACLs(client *http.Client, key string, parentVersion FastlyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, fmt.Sprintf(endpoints[serviceVersionACLs], parentVersion.Metadata["service_id"], parentVersion.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var acls []ACL

		if err := json.Unmarshal(respBody, &acls); err != nil {
			return err
		}

		for _, acl := range acls {
			resource := FastlyResource{
				ID:     acl.ID,
				Name:   acl.Name,
				Type:   TypeSvcVersionACL,
				Parent: &parentVersion,
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// captureSvcVersionDicts calls `/service/<id>/version/<number>/dictionaries` API
func captureSvcVersionDicts(client *http.Client, key string, parentVersion FastlyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, fmt.Sprintf(endpoints[serviceVersionDictionary], parentVersion.Metadata["service_id"], parentVersion.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var dicts []Dictionary

		if err := json.Unmarshal(respBody, &dicts); err != nil {
			return err
		}

		for _, dict := range dicts {
			resource := FastlyResource{
				ID:     dict.ID,
				Name:   dict.Name,
				Type:   TypeSvcVersionDict,
				Parent: &parentVersion,
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// captureSvcVersionBackends calls `/service/<id>/version/<number>/backend` API
func captureSvcVersionBackends(client *http.Client, key string, parentVersion FastlyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, fmt.Sprintf(endpoints[serviceVersionBackend], parentVersion.Metadata["service_id"], parentVersion.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var backends []Backend

		if err := json.Unmarshal(respBody, &backends); err != nil {
			return err
		}

		for _, backend := range backends {
			resource := FastlyResource{
				ID:     parentVersion.Metadata["service_id"] + "/version/" + parentVersion.ID + "/" + backend.Name, // no specific ID
				Name:   backend.Name,
				Type:   TypeSvcVersionBackend,
				Parent: &parentVersion,
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}
