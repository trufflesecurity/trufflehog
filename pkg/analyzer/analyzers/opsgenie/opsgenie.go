//go:generate generate_permissions permissions.yaml permissions.go opsgenie

package opsgenie

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

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeOpsgenie }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, ok := credInfo["key"]
	if !ok {
		return nil, analyzers.NewAnalysisError(
			"Opsgenie", "validate_credentials", "config", "", errors.New("missing key in credInfo"),
		)
	}
	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError(
			"Opsgenie", "analyze_permissions", "API", "", err,
		)
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

type User struct {
	FullName string `json:"fullName"`
	Username string `json:"username"`
	Role     struct {
		Name string `json:"name"`
	} `json:"role"`
}

type UsersJSON struct {
	Users []User `json:"data"`
}

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

	// Create new HTTP request
	var client *http.Client

	// Non-safe Opsgenie APIs are asynchronous and always return 202 if credential has the permission.
	// For Safe API Methods, use the restricted client
	if analyzers.IsMethodSafe(h.Method) {
		client = analyzers.NewAnalyzeClient(cfg)
	} else {
		client = analyzers.NewAnalyzeClientUnrestricted(cfg)
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

	permissions := make([]string, 0)
	for _, scope := range scopes {
		status, err := scope.HttpTest.RunTest(cfg, map[string]string{"Authorization": "GenieKey " + key})
		if err != nil {
			return nil, fmt.Errorf("running test: %w", err)
		}
		if status {
			permissions = append(permissions, scope.Name)
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

func getUserList(cfg *config.Config, key string) ([]User, error) {
	// Create new HTTP request
	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://api.opsgenie.com/v2/users", nil)
	if err != nil {
		return nil, err
	}

	// Add custom headers if provided
	req.Header.Set("Authorization", "GenieKey "+key)

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Decode response body
	var userList UsersJSON
	err = json.NewDecoder(resp.Body).Decode(&userList)
	if err != nil {
		return nil, err
	}

	return userList.Users, nil
}

type SecretInfo struct {
	Users       []User
	Permissions []string
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	color.Green("[!] Valid OpsGenie API key\n\n")
	printPermissions(info.Permissions)
	if len(info.Users) > 0 {
		printUsers(info.Users)
	}
	color.Yellow("\n[i] Expires: Never")

}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	var info = &SecretInfo{}

	permissions, err := checkPermissions(cfg, key)
	if err != nil {
		return nil, err
	}

	if len(permissions) == 0 {
		return nil, fmt.Errorf("invalid OpsGenie API key")
	}

	info.Permissions = permissions

	if contains(permissions, "configuration_access") {
		users, err := getUserList(cfg, key)
		if err != nil {
			return nil, fmt.Errorf("getting user list: %w", err)
		}
		info.Users = users
	}

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
