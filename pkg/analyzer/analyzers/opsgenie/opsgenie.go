package opsgenie

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

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

func checkPermissions(cfg *config.Config, key string) []string {
	scopes, err := readInScopes()
	if err != nil {
		color.Red("[x] Error reading in scopes: %s", err.Error())
		return nil
	}

	permissions := make([]string, 0)
	for _, scope := range scopes {
		status, err := scope.HttpTest.RunTest(cfg, map[string]string{"Authorization": "GenieKey " + key})
		if err != nil {
			color.Red("[x] Error running test: %s", err.Error())
			return nil
		}
		if status {
			permissions = append(permissions, scope.Name)
		}
	}

	return permissions
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

func AnalyzePermissions(cfg *config.Config, key string) {
	permissions := checkPermissions(cfg, key)
	if len(permissions) == 0 {
		color.Red("[x] Invalid OpsGenie API key")
		return
	}
	color.Green("[!] Valid OpsGenie API key\n\n")
	printPermissions(permissions)

	if contains(permissions, "Configuration Access") {
		users, err := getUserList(cfg, key)
		if err != nil {
			color.Red("[x] Error getting user list: %s", err.Error())
			return
		}
		printUsers(users)
	}

	color.Yellow("\n[i] Expires: Never")
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
