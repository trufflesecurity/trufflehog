package datadog

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"
)

// Constants and configuration
const (
	defaultTimeout = 12 * time.Second
	apiKeyHeader   = "DD-API-KEY"
	appKeyHeader   = "DD-APPLICATION-KEY"
)

// List of all DataDog domains to try
var datadogDomains = []string{
	"https://api.us5.datadoghq.com/api", // Default domain
	"https://api.app.datadoghq.com/api",
	"https://api.us3.datadoghq.com/api",
	"https://api.app.datadoghq.eu/api",
	"https://api.app.ddog-gov.com/api",
	"https://api.ap1.datadoghq.com/api",
}

// Endpoints map for API paths
var endpoints = map[string]string{
	ResourceTypeCurrentUser: "/v2/current_user",
	ResourceTypeDashboard:   "/v1/dashboard",
	ResourceTypeMonitor:     "/v1/monitor",
	ResourceTypeValidate:    "/v1/validate",
}

//go:embed scopes.json
var scopesConfig []byte

// --------------------------------
// Data models
// --------------------------------

// HttpStatusTest defines a test for checking HTTP endpoint permissions
type HttpStatusTest struct {
	Method          string `json:"method"`
	Endpoint        string `json:"endpoint"`
	ValidStatuses   []int  `json:"valid_statuses"`
	InvalidStatuses []int  `json:"invalid_statuses"`
}

// Scope represents a permission scope with a test
type Scope struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Resource    string         `json:"resource"`
	HttpTest    HttpStatusTest `json:"test"`
}

// --------------------------------
// Domain detection
// --------------------------------

// DetectDomain tries each DataDog domain to find a working one
func DetectDomain(client *http.Client, apiKey string, appKey string) (string, error) {
	for _, domain := range datadogDomains {
		// Use a simple endpoint to test if the domain works
		endpoint := domain + endpoints[ResourceTypeValidate]

		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()

		// Create request
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, http.NoBody)
		if err != nil {
			continue // Skip to next domain if request creation fails
		}

		// Add required keys in the header
		req.Header.Set(apiKeyHeader, apiKey)

		if appKey != "" {
			req.Header.Set(appKeyHeader, appKey)
		}

		resp, err := client.Do(req)

		if err != nil {
			continue // Skip to next domain if request fails
		}

		defer func() {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()

		// If we get a response that's not a connection error, this domain works
		if resp.StatusCode == http.StatusOK {
			return domain, nil
		}
	}

	return "", errors.New("unable to validate any DataDog domain with the provided API key")
}

// --------------------------------
// HTTP request utilities
// --------------------------------

// makeDataDogRequest sends an HTTP GET API request to the specified endpoint with auth tokens
func makeDataDogRequest(client *http.Client, baseURL, endpoint, method, apiKey string, appKey string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// create request
	req, err := http.NewRequestWithContext(ctx, method, baseURL+endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}

	// add required keys in the header
	req.Header.Set(apiKeyHeader, apiKey)

	if appKey != "" {
		req.Header.Set(appKeyHeader, appKey)
	}

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

// RunTest executes an HTTP test against an API endpoint with provided headers
func (h *HttpStatusTest) RunTest(client *http.Client, baseURL string, headers map[string]string) (bool, error) {
	apiKey := headers[apiKeyHeader]
	appKey := headers[appKeyHeader]

	_, statusCode, err := makeDataDogRequest(client, baseURL, h.Endpoint, h.Method, apiKey, appKey)

	if err != nil {
		fmt.Printf("Error making request: %v\n", err)
		return false, err
	}

	// Check response status code
	switch {
	case slices.Contains(h.ValidStatuses, statusCode):
		return true, nil
	case slices.Contains(h.InvalidStatuses, statusCode):
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// --------------------------------
// Data capture functions
// --------------------------------

// CaptureUserInformation retrieves and stores user information
func CaptureUserInformation(client *http.Client, baseURL, apiKey, appKey string, secretInfo *SecretInfo) error {
	caller, err := getCurrentUserInfo(client, baseURL, apiKey, appKey)
	if err != nil {
		return err
	}

	addUserToSecretInfo(caller, secretInfo)

	return nil
}

// CaptureResources retrieves and stores dashboard and monitor resources
func CaptureResources(client *http.Client, baseURL, apiKey, appKey string, secretInfo *SecretInfo) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2) // Buffer size matches the number of tasks

	// helper to launch tasks concurrently
	launchTask := func(task func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := task(); err != nil {
				errChan <- err
			}
		}()
	}

	launchTask(func() error { return captureDashboard(client, baseURL, apiKey, appKey, secretInfo) })
	launchTask(func() error { return captureMonitor(client, baseURL, apiKey, appKey, secretInfo) })

	// Wait for all tasks to complete
	wg.Wait()
	close(errChan)

	// Collect any errors
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// CapturePermissions tests and records available permissions
func CapturePermissions(client *http.Client, baseURL, apiKey, appKey string, secretInfo *SecretInfo) error {
	scopes, err := readInScopes()
	if err != nil {
		return fmt.Errorf("reading in scopes: %w", err)
	}

	permissions := make([]Permission, 0)
	headers := map[string]string{
		apiKeyHeader: apiKey,
		appKeyHeader: appKey,
	}

	for _, scope := range scopes {
		status, err := scope.HttpTest.RunTest(client, baseURL, headers)
		if err != nil {
			return fmt.Errorf("running test for scope %s: %w", scope.Name, err)
		}

		metadata := map[string]string{
			"Resource": scope.Resource,
		}

		if status {
			permission := Permission{
				Name:        scope.Name,
				Title:       scope.Title,
				Description: scope.Description,
				MetaData:    metadata,
			}
			permissions = append(permissions, permission)
		}
	}

	secretInfo.Permissions = permissions
	return nil
}

// --------------------------------
// Resource capture helper functions
// --------------------------------

// getCurrentUserInfo retrieves information about the current user
func getCurrentUserInfo(client *http.Client, baseURL, apiKey, appKey string) (*currentUserResponse, error) {
	response, statusCode, err := makeDataDogRequest(client, baseURL, endpoints[ResourceTypeCurrentUser], http.MethodGet, apiKey, appKey)
	if err != nil {
		return nil, err
	}

	switch statusCode {
	case http.StatusOK:
		var caller = &currentUserResponse{}
		if err := json.Unmarshal(response, caller); err != nil {
			return nil, fmt.Errorf("unmarshalling user response: %w", err)
		}
		return caller, nil
	case http.StatusUnauthorized:
		return nil, errors.New("invalid API key or application key")
	default:
		return nil, fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// addUserToSecretInfo adds user information to the secret info object
func addUserToSecretInfo(caller *currentUserResponse, secretInfo *SecretInfo) {
	user := User{
		Id:    caller.Data.Id,
		Name:  caller.Data.Attributes.Name,
		Email: caller.Data.Attributes.Email,
	}

	secretInfo.User = user
}

// captureDashboard retrieves dashboard information
func captureDashboard(client *http.Client, baseURL, apiKey, appKey string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeDataDogRequest(client, baseURL, endpoints[ResourceTypeDashboard], http.MethodGet, apiKey, appKey)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var dashboardResponse = &dashboardResponse{}
		if err := json.Unmarshal(response, dashboardResponse); err != nil {
			return fmt.Errorf("unmarshalling dashboard response: %w", err)
		}

		for _, dashboard := range dashboardResponse.Dashboards {
			metadata := map[string]string{
				"Layout Type":   dashboard.LayoutType,
				"URL":           dashboard.URL,
				"Author Handle": dashboard.AuthorHandle,
			}

			resource := Resource{
				ID:       dashboard.ID,
				Name:     dashboard.Title,
				Type:     ResourceTypeDashboard,
				MetaData: metadata,
			}

			secretInfo.appendResource(resource)
		}
		return nil
	case http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code for dashboard API: %d", statusCode)
	}
}

// captureMonitor retrieves monitor information
func captureMonitor(client *http.Client, baseURL, apiKey, appKey string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeDataDogRequest(client, baseURL, endpoints[ResourceTypeMonitor], http.MethodGet, apiKey, appKey)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var monitorResponse = &monitorResponse{}
		if err := json.Unmarshal(response, monitorResponse); err != nil {
			return fmt.Errorf("unmarshalling monitor response: %w", err)
		}

		for _, monitor := range *monitorResponse {
			resource := Resource{
				ID:   strconv.Itoa(monitor.ID),
				Name: monitor.Name,
				Type: ResourceTypeMonitor,
			}

			secretInfo.appendResource(resource)
		}
		return nil
	case http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code for monitor API: %d", statusCode)
	}
}

// --------------------------------
// Utility functions
// --------------------------------

// readInScopes loads permission scopes from the embedded configuration
func readInScopes() ([]Scope, error) {
	var scopes []Scope
	if err := json.Unmarshal(scopesConfig, &scopes); err != nil {
		return nil, fmt.Errorf("unmarshalling scopes config: %w", err)
	}
	return scopes, nil
}
