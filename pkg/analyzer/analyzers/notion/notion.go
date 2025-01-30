//go:generate generate_permissions permissions.yaml permissions.go notion

package notion

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
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeNotion }

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
		AnalyzerType:       analyzers.AnalyzerTypeNotion,
		Metadata:           nil,
		Bindings:           make([]analyzers.Binding, len(info.Permissions)),
		UnboundedResources: make([]analyzers.Resource, len(info.Users)),
	}

	resource := analyzers.Resource{
		Name:               info.Workspace,
		FullyQualifiedName: "notion.so/workspace/" + info.Workspace,
		Type:               "Workspace",
	}

	for idx, permission := range info.Permissions {
		result.Bindings[idx] = analyzers.Binding{
			Resource: resource,
			Permission: analyzers.Permission{
				Value: permission,
			},
		}
	}

	// We can find list of users in the current workspace
	// if the API key has read_user permission, so these can be
	// unbounded resources
	for idx, user := range info.Users {
		result.UnboundedResources[idx] = analyzers.Resource{
			Name:               user.Name,
			FullyQualifiedName: user.Id,
			Type:               user.Type, // person or bot
		}
		if user.Person.Email != "" {
			result.UnboundedResources[idx].Metadata = map[string]interface{}{
				"email": user.Person.Email,
			}
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

	// Create new HTTP request
	client := analyzers.NewAnalyzeClientUnrestricted(cfg)
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

func getPermissions(cfg *config.Config, key string) ([]string, error) {
	scopes, err := readInScopes()
	if err != nil {
		return nil, fmt.Errorf("reading in scopes: %w", err)
	}

	permissions := make([]string, 0)
	for _, scope := range scopes {
		status, err := scope.HttpTest.RunTest(cfg, map[string]string{"Authorization": "Bearer " + key, "Notion-Version": "2022-06-28"})
		if err != nil {
			return nil, fmt.Errorf("running test: %w", err)
		}
		if status {
			permissions = append(permissions, scope.Name)
		}
	}

	return permissions, nil
}

type SecretInfo struct {
	Workspace   string
	Permissions []string
	Users       []User
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	color.Green("[!] Valid Notion API key\n\n")

	color.Green("[i] Workspace: %s\n\n", info.Workspace)

	printPermissions(info.Permissions)
	if len(info.Users) > 0 {
		printUsers(info.Users)
	}
	color.Yellow("\n[i] Expires: Never")

}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	workspace, err := getWorkspace(cfg, key)
	if err != nil {
		return nil, fmt.Errorf("error getting workspace: %s", err.Error())
	}

	permissions, err := getPermissions(cfg, key)
	if err != nil {
		return nil, fmt.Errorf("error getting permissions: %s", err.Error())
	}

	readUserPermission, users, err := getUsersPermission(cfg, key)
	if err != nil {
		return nil, fmt.Errorf("error getting user permission: %s", err.Error())
	}
	if readUserPermission != "" {
		permissions = append(permissions, readUserPermission)
	}

	return &SecretInfo{
		Workspace:   workspace,
		Permissions: permissions,
		Users:       users,
	}, nil
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
	color.Yellow("\n[i] Users:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "Name", "Type", "Email"})
	for _, user := range users {
		t.AppendRow(table.Row{color.GreenString(user.Id), color.GreenString(user.Name), color.GreenString(user.Type), color.GreenString(user.Person.Email)})
	}
	t.Render()
}

func getWorkspace(cfg *config.Config, key string) (string, error) {
	// Create new HTTP request
	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://api.notion.com/v1/users/me", nil)
	if err != nil {
		return "", err
	}

	// Add custom headers if provided
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Notion-Version", "2022-06-28")

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Decode response body
	type meResponse struct {
		Bot struct {
			WorkspaceName string `json:"workspace_name"`
		} `json:"bot"`
	}
	me := &meResponse{}
	err = json.NewDecoder(resp.Body).Decode(me)
	if err != nil {
		return "", err
	}

	return me.Bot.WorkspaceName, nil
}

type User struct {
	Id     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Person struct {
		Email string `json:"email"`
	}
}

func getUsersPermission(cfg *config.Config, key string) (string, []User, error) {
	// Create new HTTP request
	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://api.notion.com/v1/users", nil)
	if err != nil {
		return "", nil, err
	}

	// Add custom headers if provided
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Notion-Version", "2022-06-28")

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return "", nil, nil // no permission
	} else if resp.StatusCode != http.StatusOK {
		return "", nil, errors.New("error checking user permissions")
	}

	// Decode response body
	type usersResponse struct {
		Results []User `json:"results"`
	}
	response := &usersResponse{}
	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return "", nil, err
	}

	// check if email is returned to determine permission
	readUserPermission := ""
	for _, user := range response.Results {
		if user.Type == "person" {
			if user.Person.Email == "" {
				readUserPermission, _ = ReadUsersWithoutEmail.ToString()
			} else {
				readUserPermission, _ = ReadUsersWithEmail.ToString()
			}
			break
		}
	}

	return readUserPermission, response.Results, nil
}
