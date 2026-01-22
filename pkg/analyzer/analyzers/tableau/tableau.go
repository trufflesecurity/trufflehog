//go:generate go run generate_permissions.go permissions.yaml permissions.go tableau
package tableau

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (a Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeTableau }

type SecretInfo struct {
	Permissions []Permission
	Role        string
	FullName    string
	Email       string
	ID          string
}

type TableauAuthResponse struct {
	Credentials struct {
		Site struct {
			ID         string `json:"id"`
			ContentURL string `json:"contentUrl"`
		} `json:"site"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Token string `json:"token"`
	} `json:"credentials"`
}

type GetUsersResponse struct {
	User User `json:"user"`
}

type User struct {
	Role     string `json:"siteRole"`
	FullName string `json:"fullName"`
	Email    string `json:"email"`
	ID       string `json:"id"`
}

type AuthenticatedPat struct {
	siteId string
	userId string
	token  string
}

type ProjectsResponse struct {
	Projects struct {
		Project []Project `json:"project"`
	} `json:"projects"`
}

type Project struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Owner struct {
		ID string `json:"id"`
	} `json:"owner"`
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	tokenName, ok := credInfo["tokenName"]
	if !ok {
		return nil, errors.New("token name not found in credentialInfo")
	}
	patSecret, ok := credInfo["patSecret"]
	if !ok {
		return nil, errors.New("pat not found in credentialInfo")
	}
	endpoint, ok := credInfo["endpoint"]
	if !ok {
		return nil, errors.New("endpoint not found in credentialInfo")
	}
	info, err := AnalyzePermissions(a.Cfg, tokenName, patSecret, endpoint)
	if err != nil {
		return nil, err
	}
	return secretInfoToAnalyzerResult(info), nil
}

func AnalyzePermissions(cfg *config.Config, patName, patSecret, endpoint string) (*SecretInfo, error) {
	client := analyzers.NewAnalyzeClientUnrestricted(cfg)

	authResp, err := authenticatePat(client, patName, patSecret, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate PAT: %v", err)
	}

	authToken := authResp.token
	usersResp, err := getUsers(client, authToken, authResp.siteId, authResp.userId, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %v", err)
	}

	mapRoleToPermissions, ok := RolePermissions[usersResp.Role]
	if !ok {
		return nil, fmt.Errorf("role %s not found in RolePermissions map", usersResp.Role)
	}
	var secretInfo = &SecretInfo{
		Permissions: mapRoleToPermissions,
		Role:        usersResp.Role,
		FullName:    usersResp.FullName,
		Email:       usersResp.Email,
		ID:          usersResp.ID,
	}

	return secretInfo, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, patName, patSecret, endpoint string) {
	analyzer := Analyzer{Cfg: cfg}
	credInfo := map[string]string{
		"tokenName": patName,
		"patSecret": patSecret,
		"endpoint":  endpoint,
	}
	result, err := analyzer.Analyze(context.Background(), credInfo)
	if err != nil {
		fmt.Printf("Error analyzing Tableau PAT: %v\n", err)
		return
	}

	printUserIdentity(&result.Metadata)
	printPermissionsTable(&result.Bindings)
	printPermissionNote()
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}
	result := analyzers.AnalyzerResult{
		AnalyzerType:       analyzers.AnalyzerTypeTableau,
		UnboundedResources: []analyzers.Resource{},
		Metadata: map[string]any{
			"role":     info.Role,
			"fullName": info.FullName,
			"email":    info.Email,
			"id":       info.ID,
		},
	}
	result.Bindings = BindPermissionsToResource(info)

	return &result
}
func groupResultsByResourceType(bindings *[]analyzers.Binding) map[string][]analyzers.Binding {
	grouped := make(map[string][]analyzers.Binding)
	for _, binding := range *bindings {
		resourceType := binding.Resource.Type
		grouped[resourceType] = append(grouped[resourceType], binding)
	}
	return grouped
}

func authenticatePat(client *http.Client, patName, patSecret, endpoint string) (*AuthenticatedPat, error) {
	url := fmt.Sprintf("https://%s/api/3.26/auth/signin", endpoint)
	TableauAuthRequest := map[string]any{
		"credentials": map[string]any{
			"personalAccessTokenName":   patName,
			"personalAccessTokenSecret": patSecret,
			"site":                      map[string]any{},
		},
	}
	jsonData, err := json.Marshal(TableauAuthRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal auth request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentication failed with status code: %d", resp.StatusCode)
	}
	var authResp TableauAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &AuthenticatedPat{
		siteId: authResp.Credentials.Site.ID,
		userId: authResp.Credentials.User.ID,
		token:  authResp.Credentials.Token,
	}, nil
}

func getUsers(client *http.Client, authToken, siteId, userId, endpoint string) (*User, error) {
	url := fmt.Sprintf("https://%s/api/3.26/sites/%s/users/%s", endpoint, siteId, userId)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Tableau-Auth", authToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get users failed with status code: %d", resp.StatusCode)
	}

	var usersResp GetUsersResponse
	if err := json.NewDecoder(resp.Body).Decode(&usersResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &User{
		Role:     usersResp.User.Role,
		FullName: usersResp.User.FullName,
		Email:    usersResp.User.Email,
		ID:       usersResp.User.ID,
	}, nil
}

func BindPermissionsToResource(info *SecretInfo) []analyzers.Binding {
	bindings := make([]analyzers.Binding, 0)
	for _, perm := range info.Permissions {
		permStr, err := perm.ToString()
		if err != nil {
			continue
		}
		pe := strings.SplitN(permStr, ":", 2)
		resourceName := pe[0]
		permissionPart := pe[1]
		bindings = append(bindings, analyzers.Binding{
			Resource: analyzers.Resource{
				Name:               resourceName,
				Type:               resourceName,
				FullyQualifiedName: resourceName,
			},
			Permission: analyzers.Permission{
				Value:  permissionPart,
				Parent: nil,
			},
		})
	}

	return bindings
}

func printUserIdentity(metadata *map[string]any) {
	t := table.NewWriter()
	t.SetTitle("User Information")

	t.AppendHeader(table.Row{"Field", "Value"})

	t.AppendRow(table.Row{"Full Name", (*metadata)["fullName"]})
	t.AppendRow(table.Row{"Email", (*metadata)["email"]})
	t.AppendRow(table.Row{"Role", (*metadata)["role"]})

	t.SetStyle(table.StyleRounded)
	fmt.Println(t.Render())
}

func printPermissionsTable(bindings *[]analyzers.Binding) {
	grouped := groupResultsByResourceType(bindings)

	for resourceType, bindings := range grouped {
		t := table.NewWriter()
		t.SetTitle(strings.ToUpper(resourceType) + " PERMISSIONS")

		t.AppendHeader(table.Row{
			"Resource Name",
			"Permission",
		})

		for _, b := range bindings {
			t.AppendRow(table.Row{
				b.Resource.Name,
				b.Permission.Value,
			})
		}

		t.SetStyle(table.StyleRounded)
		fmt.Println(t.Render())
	}
}

func printPermissionNote() {
	fmt.Println()
	fmt.Println("NOTE")
	fmt.Println("----")
	fmt.Println("• Permissions shown are derived from the user's Tableau site role.")
	fmt.Println("• Object-level permissions (Project, Workbook, etc.) may further restrict access.")
	fmt.Println("• Explicit DENY rules always override role-based permissions.")
	fmt.Println()
}
