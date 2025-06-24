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
	serviceVersionDictionaries
	serviceVersionBackends
	serviceVersionDomains
	serviceVersionHealthChecks
	configStores
	secretStores
	tlsPrivateKeys
	tlsCertificates
	tlsDomains
	invoices
)

var (
	baseURL = "https://api.fastly.com"

	// endpoints contain Fastly API endpoints
	endpoints = map[endpoint]string{
		selfToken:                  "/tokens/self",
		currentUser:                "/current_user",
		userTokens:                 "/tokens",
		automationTokens:           "/automation-tokens",
		service:                    "/service",
		serviceVersions:            "/service/%s/version",                // require service id
		serviceVersionACLs:         "/service/%s/version/%s/acl",         // require service id and version number
		serviceVersionDictionaries: "/service/%s/version/%s/dictionary",  // require service id and version number
		serviceVersionBackends:     "/service/%s/version/%s/backend",     // require service id and version number
		serviceVersionDomains:      "/service/%s/version/%s/domain",      // require service id and version number
		serviceVersionHealthChecks: "/service/%s/version/%s/healthcheck", // require service id and version number
		configStores:               "/resources/stores/config",
		secretStores:               "/resources/stores/secret",
		tlsPrivateKeys:             "/tls/private_keys",
		tlsCertificates:            "/tls/certificates",
		tlsDomains:                 "/tls/domains",
		invoices:                   "/billing/v3/invoices",

		/*
			API:
			- /service/service_id/version/version_id/package (The use of this API is discouraged as per documentation due to limited availability release)
			- /tls/bulk/certificates (The use of this API is discouraged as per documentation due to limited availability release)
			- /security/workspaces (This Fastly Security API is only available to customers with access to the Next-Gen WAF product )
			- /events (This API just returns the account events like user logged in or user logged out etc)

			Utilities API Docs:
			Some of these APIs are deprecated while others return same response for everyone with a global access key.
			- https://www.fastly.com/documentation/reference/api/utils/
		*/
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
			launchTask(func() error { return captureSvcVersionDomains(client, key, version, secretInfo) })
			launchTask(func() error { return captureSvcVersionHealthChecks(client, key, version, secretInfo) })
		}

		return nil
	})

	launchTask(func() error { return captureConfigStores(client, key, secretInfo) })
	launchTask(func() error { return captureSecretStores(client, key, secretInfo) })
	launchTask(func() error { return capturePrivateKeys(client, key, secretInfo) })
	launchTask(func() error { return captureCertificates(client, key, secretInfo) })
	launchTask(func() error { return captureTLSDomains(client, key, secretInfo) })
	launchTask(func() error { return captureInvoices(client, key, secretInfo) })

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
	respBody, statusCode, err := makeFastlyRequest(client, fmt.Sprintf(endpoints[serviceVersionDictionaries], parentVersion.Metadata["service_id"], parentVersion.ID), key)
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
	respBody, statusCode, err := makeFastlyRequest(client, fmt.Sprintf(endpoints[serviceVersionBackends], parentVersion.Metadata["service_id"], parentVersion.ID), key)
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
				ID:     parentVersion.Metadata["service_id"] + "/version/" + parentVersion.ID + "/backend/" + backend.Name, // no specific ID
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

// captureSvcVersionDomains calls `/service/<id>/version/<number>/domain` API
func captureSvcVersionDomains(client *http.Client, key string, parentVersion FastlyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, fmt.Sprintf(endpoints[serviceVersionDomains], parentVersion.Metadata["service_id"], parentVersion.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var domains []Domain

		if err := json.Unmarshal(respBody, &domains); err != nil {
			return err
		}

		for _, domain := range domains {
			resource := FastlyResource{
				ID:     parentVersion.Metadata["service_id"] + "/version/" + parentVersion.ID + "/domain/" + domain.Name, // no specific ID
				Name:   domain.Name,
				Type:   TypeSvcVersionDomain,
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

// captureSvcVersionHealthChecks calls `/service/<id>/version/<number>/healthcheck` API
func captureSvcVersionHealthChecks(client *http.Client, key string, parentVersion FastlyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, fmt.Sprintf(endpoints[serviceVersionHealthChecks], parentVersion.Metadata["service_id"], parentVersion.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var healthChecks []HealthCheck

		if err := json.Unmarshal(respBody, &healthChecks); err != nil {
			return err
		}

		for _, healthCheck := range healthChecks {
			resource := FastlyResource{
				ID:     parentVersion.Metadata["service_id"] + "/version/" + parentVersion.ID + "/healthcheck/" + healthCheck.Name, // no specific ID
				Name:   healthCheck.Name,
				Type:   TypeSvcVersionHealthCheck,
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

// captureConfigStores calls `/resources/stores/config` API
func captureConfigStores(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, endpoints[configStores], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var configs []ConfigStore

		if err := json.Unmarshal(respBody, &configs); err != nil {
			return err
		}

		for _, config := range configs {
			resource := FastlyResource{
				ID:   config.ID,
				Name: config.Name,
				Type: TypeConfigStore,
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

// captureSecretStores calls `/resources/stores/secret` API
func captureSecretStores(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, endpoints[secretStores], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var secretStores SecretStoreData

		if err := json.Unmarshal(respBody, &secretStores); err != nil {
			return err
		}

		for _, secret := range secretStores.Data {
			resource := FastlyResource{
				ID:   secret.ID,
				Name: secret.Name,
				Type: TypeSecretStore,
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

// capturePrivateKeys calls `/tls/private_keys` API
func capturePrivateKeys(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, endpoints[tlsPrivateKeys], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var privateKeys TLSPrivateKeyData

		if err := json.Unmarshal(respBody, &privateKeys); err != nil {
			return err
		}

		for _, privateKey := range privateKeys.Data {
			resource := FastlyResource{
				ID:   privateKey.ID,
				Name: privateKey.Name,
				Type: TypeTLSPrivateKey,
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

// captureCertificates calls `/tls/certificates` API
func captureCertificates(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, endpoints[tlsCertificates], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var certData TLSCertificatesData

		if err := json.Unmarshal(respBody, &certData); err != nil {
			return err
		}

		for _, cert := range certData.Data {
			resource := FastlyResource{
				ID:   cert.ID,
				Name: cert.Name,
				Type: TypeTLSCertificate,
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

// captureTLSDomains calls `/tls/domains` API
func captureTLSDomains(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, endpoints[tlsDomains], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var domainData TLSDomainsData

		if err := json.Unmarshal(respBody, &domainData); err != nil {
			return err
		}

		for _, domain := range domainData.Data {
			resource := FastlyResource{
				ID:   domain.ID,
				Name: domain.ID,
				Type: TypeTLSDomain,
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

// captureInvoices calls `/billing/v3/invoices` API
func captureInvoices(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeFastlyRequest(client, endpoints[invoices], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var invoices InvoicesData

		if err := json.Unmarshal(respBody, &invoices); err != nil {
			return err
		}

		for _, invoice := range invoices.Data {
			resource := FastlyResource{
				ID:   invoice.CustomerID + "/region/" + invoice.Region + "/statement/" + invoice.StatementNo + "/invoice/" + invoice.ID,
				Name: invoice.ID, // no specific name
				Type: TypeInvoice,
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
