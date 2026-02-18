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
	"github.com/jedib0t/go-pretty/v6/table"
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
		return nil, analyzers.NewAnalysisError(
			"Notion", "validate_credentials", "config", "", errors.New("missing key in credInfo"),
		)
	}
	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError(
			"Notion", "analyze_permissions", "API", "", err,
		)
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
		UnboundedResources: make([]analyzers.Resource, 0, len(info.WorkspaceUsers)),
	}

	resource := analyzers.Resource{
		Name:               info.Bot.Name,
		FullyQualifiedName: "notion.so/bot/" + info.Bot.Id,
		Type:               info.Bot.Type,
		Metadata: map[string]interface{}{
			"workspace": info.Bot.GetWorkspaceName(),
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

	// We can find list of users in the current workspace
	// if the API key has read_user permission, so these can be
	// unbounded resources
	for _, user := range info.WorkspaceUsers {
		if info.Bot.Id == user.Id {
			// Skip the bot itself
			continue
		}
		unboundresource := analyzers.Resource{
			Name:               user.Name,
			FullyQualifiedName: fmt.Sprintf("notion.so/%s/%s", user.Type, user.Id),
			Type:               user.Type, // person or bot
		}
		if user.Person.Email != "" {
			unboundresource.Metadata = map[string]interface{}{
				"email": user.Person.Email,
			}
		}

		result.UnboundedResources = append(result.UnboundedResources, unboundresource)
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

	permissions := make([]string, 0, len(scopes))
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
	Bot            *bot
	WorkspaceUsers []user
	Permissions    []string
}

type user struct {
	Id     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Person struct {
		Email string `json:"email"`
	}
}

type bot struct {
	Id   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	Bot  struct {
		Owner *struct {
			Type string `json:"type"`
		}
		WorkspaceName string `json:"workspace_name"`
	} `json:"bot"`
}

func (b *bot) GetWorkspaceName() string {
	return b.Bot.WorkspaceName
}

func (b *bot) OwnedBy() string {
	if b.Bot.Owner != nil {
		return b.Bot.Owner.Type
	}
	return "N/A"
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	color.Green("[!] Valid Notion API key\n\n")

	color.Green("[i] Bot: %s (%s)\n", info.Bot.Name, info.Bot.Id)
	color.Green("[i] Bot Owned By: %s\n", info.Bot.OwnedBy())

	if info.Bot.GetWorkspaceName() != "" {
		color.Green("[i] Workspace: %s\n\n", info.Bot.GetWorkspaceName())
	}

	printPermissions(info.Permissions)
	if len(info.WorkspaceUsers) > 0 {
		printUsers(info.WorkspaceUsers)
	}
	color.Yellow("\n[i] Expires: Never")

}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	permissions := make([]string, 0)

	client := analyzers.NewAnalyzeClient(cfg)

	bot, err := getBotInfo(client, key)
	if err != nil {
		return nil, err
	}

	credPermissions, err := getPermissions(cfg, key)
	if err != nil {
		return nil, err
	}

	permissions = append(permissions, credPermissions...)

	users, err := getWorkspaceUsers(client, key)
	if err != nil {
		return nil, fmt.Errorf("error getting user permission: %s", err.Error())
	}

	// check if email is returned in users to determine permission
	for _, user := range users {
		if user.Type == "person" {
			if user.Person.Email == "" {
				permissions = append(permissions, PermissionStrings[ReadUsersWithoutEmail])
			} else {
				permissions = append(permissions, PermissionStrings[ReadUsersWithEmail])
			}
			break
		}
	}
	return &SecretInfo{
		Bot:            bot,
		Permissions:    permissions,
		WorkspaceUsers: users,
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

func printUsers(users []user) {
	color.Yellow("\n[i] Workspace Users:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "Name", "Type", "Email"})
	for _, user := range users {
		t.AppendRow(table.Row{color.GreenString(user.Id), color.GreenString(user.Name), color.GreenString(user.Type), color.GreenString(user.Person.Email)})
	}
	t.Render()
}

func getBotInfo(client *http.Client, key string) (*bot, error) {
	// Create new HTTP request
	req, err := http.NewRequest(http.MethodGet, "https://api.notion.com/v1/users/me", http.NoBody)
	if err != nil {
		return nil, err
	}

	// Add custom headers if provided
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Notion-Version", "2022-06-28")

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		me := &bot{}
		err = json.NewDecoder(resp.Body).Decode(me)
		if err != nil {
			return nil, err
		}
		return me, nil
	case http.StatusUnauthorized:
		return nil, errors.New("invalid API key")
	default:
		return nil, errors.New("error getting bot info")
	}
}

// Decode response body
type usersResponse struct {
	Results []user `json:"results"`
}

func getWorkspaceUsers(client *http.Client, key string) ([]user, error) {
	// Create new HTTP request
	req, err := http.NewRequest(http.MethodGet, "https://api.notion.com/v1/users", http.NoBody)
	if err != nil {
		return nil, err
	}

	// Add custom headers if provided
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Notion-Version", "2022-06-28")

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		response := &usersResponse{}
		err = json.NewDecoder(resp.Body).Decode(response)
		if err != nil {
			return nil, err
		}
		return response.Results, nil
	case http.StatusUnauthorized:
		return nil, errors.New("invalid API key")
	case http.StatusForbidden:
		return nil, nil // no permission
	case http.StatusNotFound:
		return nil, errors.New("workspace not found")
	default:
		return nil, errors.New("error checking user permissions")
	}

}
