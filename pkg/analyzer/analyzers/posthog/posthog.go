//go:generate generate_permissions permissions.yaml permissions.go posthog

package posthog

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

const (
	USDomain = "https://us.posthog.com"
	EUDomain = "https://eu.posthog.com"
)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypePosthog }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, ok := credInfo["key"]
	if !ok {
		return nil, errors.New("missing key in credInfo")
	}
	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, err
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}
	result := analyzers.AnalyzerResult{
		AnalyzerType:       analyzers.AnalyzerTypeOpsgenie,
		Metadata:           nil,
		Bindings:           make([]analyzers.Binding, len(info.Permissions)),
		UnboundedResources: make([]analyzers.Resource, len(info.Users)),
	}

	// Opsgenie has API integrations, so the key does not belong
	// to a particular user or account, it itself is a resource
	resource := analyzers.Resource{
		Name:               "Opsgenie API Integration Key",
		FullyQualifiedName: "Opsgenie API Integration Key",
		Type:               "API Key",
		Metadata: map[string]any{
			"expires": "never",
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

	// We can find list of users in the current account
	// if the API key has Configuration Access, so these can be
	// unbounded resources
	for idx, user := range info.Users {
		result.UnboundedResources[idx] = analyzers.Resource{
			Name:               user.FullName,
			FullyQualifiedName: user.Username,
			Type:               "user",
			Metadata: map[string]any{
				"username": user.Username,
				"role":     user.Role.Name,
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

func (h *HttpStatusTest) RunTest(cfg *config.Config, client *http.Client, headers map[string]string) (bool, error) {
	// If body data, marshal to JSON
	var data io.Reader
	if h.Payload != nil {
		jsonData, err := json.Marshal(h.Payload)
		if err != nil {
			return false, err
		}
		data = bytes.NewBuffer(jsonData)
	}

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
	Name string    `json:"name"`
	Test ScopeTest `json:"test"`
}

type ScopeTest struct {
	Read  *HttpStatusTest `json:"read"`
	Write *HttpStatusTest `json:"write"`
}

func readInScopes() ([]Scope, error) {
	var scopes []Scope
	if err := json.Unmarshal(scopesConfig, &scopes); err != nil {
		return nil, err
	}

	return scopes, nil
}

func checkPermissions(cfg *config.Config, client *http.Client, domain string, org *organization, key string) ([]string, error) {
	scopes, err := readInScopes()
	if err != nil {
		return nil, fmt.Errorf("reading in scopes: %w", err)
	}

	permissions := make([]string, 0)
	for _, scope := range scopes {
		var status bool
		var err error
		if scope.Test.Write != nil {
			status, err = scope.Test.Write.RunTest(cfg, client, map[string]string{"Authorization": "Bearer " + key})
			if err != nil {
				return nil, fmt.Errorf("running test: %w", err)
			}
		}
		if status {
			// if write exists, read also exists
			permissions = append(permissions, scope.Name+":write")
			permissions = append(permissions, scope.Name+":read")
		} else {
			status, err = scope.Test.Read.RunTest(cfg, client, map[string]string{"Authorization": "Bearer " + key})
			if err != nil {
				return nil, fmt.Errorf("running test: %w", err)
			}
			if status {
				permissions = append(permissions, scope.Name+":read")
			}
		}

	}

	return permissions, nil
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

type organizationPermissions struct {
	Organization *organization
	Permissions  []Permission
}

type projectPermissions struct {
	Organization *organization
	Project      *project
	Permissions  []Permission
}

type SecretInfo struct {
	isValid                 bool
	user                    *user
	organizationPermissions []organizationPermissions
	projectPermissions      []projectPermissions
	generalPermissions      []Permission
	unverifiedPermissions   map[Permission]struct{}
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	color.Green("[!] Valid Posthog API key\n\n")
	printPermissions(info.Permissions)
	if len(info.Users) > 0 {
		printUsers(info.Users)
	}
	color.Yellow("\n[i] Expires: Never")

}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	var info = &SecretInfo{}

	// These are permissions that cannot be verified due to no endpoint available
	info.unverifiedPermissions = map[Permission]struct{}{
		PluginWrite:               struct{}{},
		SharingConfigurationRead:  struct{}{},
		SharingConfigurationWrite: struct{}{},
		WebhookRead:               struct{}{},
		WebhookWrite:              struct{}{},
	}

	client := analyzers.NewAnalyzeClient(cfg)

	// we need to determine if the key is for US or EU domain
	domain, user, err := resolveDomainAndUser(cfg, client, key)
	if err != nil {
		return nil, fmt.Errorf("Invalid API Key: %w", err)
	}
	info.isValid = true

	info.generalPermissions = make([]Permission, 0)
	if user != nil {
		info.user = user
		info.generalPermissions = append(info.generalPermissions, UserRead)
	}

	// Most posthog API scopes are bound to projects and organization, so to determine the scopes we need to first get the organization and projects.
	// If the key has user:read scope, we will get the user above which contains the organizations and projects.
	// If the key does not have user:read scope, we can call the /organizations/@current endpoint to get the
	// organization and projects. If the key does not have organization:read scope as well, we cannot determine any scope.
	org, err := getOrganization(cfg, client, domain, key)
	if err != nil {
		return nil, err
	}
	if org == nil && user == nil {
		// can't determine any scopes
		for permission := range PermissionStrings {
			info.unverifiedPermissions[permission] = struct{}{}
		}
		return info, nil
	}
	if org == nil {
		org = &user.Organization
	}

	permissions, err := checkPermissions(cfg, client, domain, org, key)
	if err != nil {
		return nil, err
	}

	info.Permissions = permissions

	return info, nil
}

type user struct {
	UUID         string       `json:"uuid"`
	FirstName    string       `json:"first_name"`
	LastName     string       `json:"last_name"`
	Email        string       `json:"email"`
	Organization organization `json:"organization"`
}

type organization struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Projects []project `json:"projects"`
}

type project struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// resolves the domain and user (if permission exists) by calling the /users/@me method for both US and EU domains
// if the response is 200 OK, it means the domain is valid and user:read permission is also there
// if the response is 403 Forbidden, it means the domain is valid but user:read permission is not there
// if the response is 401 Unauthorized, it means the domain is invalid
func resolveDomainAndUser(cfg *config.Config, client *http.Client, key string) (string, *user, error) {

	domains := []string{USDomain, EUDomain}
	for _, domain := range domains {
		req, err := http.NewRequest(http.MethodGet, domain+"/api/users/@me/", nil)
		if err != nil {
			return "", nil, err
		}
		req.Header.Set("Authorization", "Bearer "+key)

		// Execute HTTP Request
		resp, err := client.Do(req)
		if err != nil {
			return "", nil, err
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			// domain is valid and user permission also exists
			var userInfo user
			if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
				return "", nil, err
			}
			return domain, &userInfo, nil
		case http.StatusForbidden:
			// domain is valid but user permission does not exist
			return domain, nil, nil
		case http.StatusUnauthorized:
			// domain is invalid
			continue
		default:
			// unexpected status code
			return "", nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}
	}
	return "", nil, fmt.Errorf("invalid Posthog API key")
}

func getOrganization(cfg *config.Config, client *http.Client, domain string, key string) (*organization, error) {
	req, err := http.NewRequest(http.MethodGet, domain+"/api/organizations/@current/", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var org organization
		if err := json.NewDecoder(resp.Body).Decode(&org); err != nil {
			return nil, err
		}
		return &org, nil
	case http.StatusForbidden:
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
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

func printUsers(users []User) {
	color.Green("\n[i] Users:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Username", "Role"})
	for _, user := range users {
		t.AppendRow(table.Row{color.GreenString(user.FullName), color.GreenString(user.Username), color.GreenString(user.Role.Name)})
	}
	t.Render()
}
