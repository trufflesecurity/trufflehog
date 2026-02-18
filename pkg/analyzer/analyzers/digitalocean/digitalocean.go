//go:generate generate_permissions permissions.yaml permissions.go digitalocean

package digitalocean

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

// to avoid rate limiting
const MAX_CONCURRENT_TESTS = 10

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeDigitalOcean }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, ok := credInfo["key"]
	if !ok {
		return nil, analyzers.NewAnalysisError(
			"DigitalOcean", "validate_credentials", "config", "", errors.New("missing key in credInfo"),
		)
	}
	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError(
			"DigitalOcean", "analyze_permissions", "API", "", err,
		)
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}
	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeDigitalOcean,
		Metadata:     nil,
		Bindings:     make([]analyzers.Binding, len(info.Permissions)),
	}

	resource := analyzers.Resource{
		Name:               info.User.Name,
		FullyQualifiedName: info.User.UUID,
		Type:               "User",
		Metadata: map[string]any{
			"email":  info.User.Email,
			"status": info.User.Status,
		},
	}

	for idx, permission := range info.Permissions {
		result.Bindings[idx] = analyzers.Binding{
			Resource: resource,
			Permission: analyzers.Permission{
				Value: permission,
			},
		}
	}

	return &result
}

//go:embed scopes.json
var scopesConfig []byte

type HttpStatusTest struct {
	Endpoint        string      `json:"endpoint"`
	Method          string      `json:"method"`
	Payload         interface{} `json:"payload"`
	ValidStatuses   []int       `json:"valid_status_code"`
	InvalidStatuses []int       `json:"invalid_status_code"`
}

func StatusContains(status int, vals []int) bool {
	for _, v := range vals {
		if status == v {
			return true
		}
	}
	return false
}

func (h *HttpStatusTest) RunTest(cfg *config.Config, headers map[string]string) (bool, error) {
	// If body data, marshal to JSON
	var data io.Reader
	if h.Payload != nil {
		jsonData, err := json.Marshal(h.Payload)
		if err != nil {
			return false, err
		}
		data = bytes.NewBuffer(jsonData)
	}

	client := analyzers.NewAnalyzeClient(cfg)

	req, err := http.NewRequest(h.Method, h.Endpoint, data)
	if err != nil {
		return false, err
	}

	// Add custom headers if provided
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Check response status code
	switch {
	case StatusContains(resp.StatusCode, h.ValidStatuses):
		return true, nil
	case StatusContains(resp.StatusCode, h.InvalidStatuses):
		return false, nil
	default:
		return false, errors.New("error checking response status code")
	}
}

type Scope struct {
	Name     string         `json:"name"`
	HttpTest HttpStatusTest `json:"test"`
}

func readInScopes() ([]Scope, error) {
	var scopes []Scope
	if err := json.Unmarshal(scopesConfig, &scopes); err != nil {
		return nil, err
	}

	return scopes, nil
}

func checkPermissions(cfg *config.Config, key string) ([]string, error) {
	scopes, err := readInScopes()
	if err != nil {
		return nil, fmt.Errorf("reading in scopes: %w", err)
	}

	var (
		permissions = make([]string, 0, len(scopes))
		mu          sync.Mutex
		wg          sync.WaitGroup
		slots       = make(chan struct{}, MAX_CONCURRENT_TESTS)
		errCh       = make(chan error, 1)
	)

	for _, scope := range scopes {
		wg.Add(1)
		go func(scope Scope) {
			defer wg.Done()

			// acquire a slot
			slots <- struct{}{}
			defer func() { <-slots }()

			status, err := scope.HttpTest.RunTest(cfg, map[string]string{"Authorization": "Bearer " + key})
			if err != nil {
				// send first error and ignore the rest
				select {
				case errCh <- fmt.Errorf("Scope %s: %w", scope.Name, err):
				default:
				}
				return
			}
			if status {
				mu.Lock()
				permissions = append(permissions, scope.Name)
				mu.Unlock()
			}
		}(scope)
	}

	// wait for all goroutines to finish or an error to occur
	go func() {
		wg.Wait()
		close(errCh)
	}()

	if err := <-errCh; err != nil {
		return nil, err
	}

	return permissions, nil
}

type user struct {
	Email  string `json:"email"`
	Name   string `json:"name"`
	UUID   string `json:"uuid"`
	Status string `json:"status"`
}

type userJSON struct {
	Account user `json:"account"`
}

func getUser(cfg *config.Config, token string) (*user, error) {
	// Create new HTTP request
	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://api.digitalocean.com/v2/account", nil)
	if err != nil {
		return nil, err
	}

	// Add custom headers if provided
	req.Header.Set("Authorization", "Bearer "+token)

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Decode response body
		var response userJSON
		err = json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return nil, err
		}

		return &response.Account, nil
	case http.StatusUnauthorized:
		return nil, errors.New("invalid token")
	default:
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

type SecretInfo struct {
	User        user
	Permissions []string
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	color.Green("[!] Valid DigitalOcean API key\n\n")

	color.Yellow("[i] User: %s (%s)\n\n", info.User.Name, info.User.Email)

	printPermissions(info.Permissions)
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	var info = &SecretInfo{}

	user, err := getUser(cfg, key)
	if err != nil {
		return nil, err
	}
	info.User = *user

	permissions, err := checkPermissions(cfg, key)
	if err != nil {
		return nil, err
	}

	if len(permissions) == 0 {
		return nil, fmt.Errorf("invalid DigitalOcean API key")
	}

	info.Permissions = permissions

	return info, nil
}

func printPermissions(permissions []string) {
	color.Yellow("[i] Permissions:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Permission"})
	for _, permission := range permissions {
		t.AppendRow(table.Row{color.GreenString(permission)})
	}
	t.Render()
}
