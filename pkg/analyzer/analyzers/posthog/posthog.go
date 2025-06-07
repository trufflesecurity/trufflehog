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
	"strconv"
	"strings"

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
		AnalyzerType: analyzers.AnalyzerTypePosthog,
		Metadata:     nil,
		Bindings:     make([]analyzers.Binding, 0),
	}

	if info.orgPermissions == nil {
		// no permissions to check
		return &result
	}

	if info.user != nil {
		// for user resource
		userResource := analyzers.Resource{
			Name:               info.user.FirstName + " " + info.user.LastName,
			FullyQualifiedName: info.user.UUID,
			Type:               "user",
		}
		analyzerPermission := analyzers.Permission{
			Value: PermissionStrings[UserRead],
		}
		result.Bindings = append(result.Bindings, analyzers.Binding{
			Resource:   userResource,
			Permission: analyzerPermission,
		})
	}

	// for organization permissions, we need to bind the permissions to the organization resource
	organizationResource := analyzers.Resource{
		Name:               info.organization.Name,
		FullyQualifiedName: info.organization.ID,
		Type:               "organization",
	}
	for _, permission := range info.orgPermissions {
		if value, ok := PermissionStrings[permission]; ok {
			analyzerPermission := analyzers.Permission{
				Value: value,
			}
			result.Bindings = append(result.Bindings, analyzers.Binding{
				Resource:   organizationResource,
				Permission: analyzerPermission,
			})
		}
	}

	// for project permissions, we need to bind the permissions to the project resource and organization as the parent resource
	for _, projectPermission := range info.projectPermissions {
		projectResource := analyzers.Resource{
			Name:               projectPermission.Project.Name,
			FullyQualifiedName: strconv.FormatInt(projectPermission.Project.ID, 10),
			Type:               "project",
			Parent:             &organizationResource,
		}
		for _, permission := range projectPermission.Permissions {
			permissionStr, _ := permission.ToString()
			analyzerPermission := analyzers.Permission{
				Value: permissionStr,
			}
			result.Bindings = append(result.Bindings, analyzers.Binding{
				Resource:   projectResource,
				Permission: analyzerPermission,
			})
		}
	}

	return &result
}

//go:embed scopes.json
var scopesConfigBytes []byte

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

func (h *HttpStatusTest) RunTest(cfg *config.Config, client *http.Client, domain string, headers map[string]string, args ...any) (bool, error) {
	// If body data, marshal to JSON
	var data io.Reader
	if h.Payload != nil {
		jsonData, err := json.Marshal(h.Payload)
		if err != nil {
			return false, err
		}
		data = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(h.Method, fmt.Sprintf(domain+h.Endpoint, args...), data)
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
		fmt.Println(h.Method, h.Endpoint)
		return false, errors.New("error checking response status code")
	}
}

type ScopesConfig struct {
	GeneralScopes      []Scope `json:"general_scopes"`
	OrganizationScopes []Scope `json:"organization_scopes"`
	ProjectScopes      []Scope `json:"project_scopes"`
}

type Scope struct {
	Name string    `json:"name"`
	Test ScopeTest `json:"test"`
}

type ScopeTest struct {
	Read  *HttpStatusTest `json:"read"`
	Write *HttpStatusTest `json:"write"`
}

func readInScopesConfig() (*ScopesConfig, error) {
	var scopesConfig ScopesConfig
	if err := json.Unmarshal(scopesConfigBytes, &scopesConfig); err != nil {
		return nil, err
	}

	return &scopesConfig, nil
}

func checkPermissions(cfg *config.Config, client *http.Client, domain string, key string, scopes []Scope, args ...any) ([]Permission, error) {

	permissions := make([]Permission, 0)
	headers := map[string]string{"Authorization": "Bearer " + key}
	for _, scope := range scopes {
		var status bool
		var err error
		if scope.Test.Write != nil {
			status, err = scope.Test.Write.RunTest(cfg, client, domain, headers, args...)
			if err != nil {
				return nil, fmt.Errorf("running test: %w", err)
			}
		}
		if status {
			if permission, ok := StringToPermission[scope.Name+":write"]; ok {
				permissions = append(permissions, permission)
			}
			// if write exists, read also exists
			if permission, ok := StringToPermission[scope.Name+":read"]; ok {
				permissions = append(permissions, permission)
			}
		} else {
			status, err = scope.Test.Read.RunTest(cfg, client, domain, headers, args...)
			if err != nil {
				return nil, fmt.Errorf("running test: %w", err)
			}
			if status {
				if permission, ok := StringToPermission[scope.Name+":read"]; ok {
					permissions = append(permissions, permission)
				}
			}
		}

	}

	return permissions, nil
}

type ProjectPermissions struct {
	Project     *Project
	Permissions []Permission
}

type SecretInfo struct {
	user               *User
	organization       *Organization
	orgPermissions     []Permission
	projectPermissions []ProjectPermissions
	// generalPermissions      []Permission
	unverifiedPermissions map[Permission]struct{}
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	color.Green("[!] Valid Posthog API key")
	color.Yellow("[i] Expires: Never")
	if info.user != nil {
		printUser(*info.user)
	}

	if info.organization == nil {
		color.Yellow("\n[i] No permissions were verified for this key because the key does not have one of the necessary permissions (user:read or organization:read) required to verifiy other permissions.")
	}

	if info.orgPermissions != nil {
		printOrganizationPermissions(*info.organization, info.orgPermissions)
	}
	if len(info.projectPermissions) > 0 {
		printProjectPermissions(info.projectPermissions)
	}
	printUnverifiedPermissions(info.unverifiedPermissions)

}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	var info = &SecretInfo{}

	// These are permissions that cannot be verified due to no endpoint available
	info.unverifiedPermissions = map[Permission]struct{}{
		ErrorTrackingRead:         {},
		ErrorTrackingWrite:        {},
		SharingConfigurationRead:  {},
		SharingConfigurationWrite: {},
		WebhookRead:               {},
		WebhookWrite:              {},
	}

	client := analyzers.NewAnalyzeClient(cfg)

	// we need to determine if the key is for US or EU domain
	domain, user, err := resolveDomainAndUser(cfg, client, key)
	if err != nil {
		return nil, fmt.Errorf("Invalid API Key: %w", err)
	}

	info.user = user

	// Most posthog API scopes are bound to projects and organization, so to determine the scopes we need to first get the organization and projects.
	// If the key has user:read scope, we will get the user above which contains the organizations and projects.
	// If the key does not have user:read scope, we can call the /organizations/@current endpoint to get the
	// organization and projects. If the key does not have organization:read scope as well, we cannot determine any scope.
	var org *Organization
	if user == nil {
		org, err = getOrganization(cfg, client, domain, key)
		if err != nil {
			return nil, err
		}
		if org == nil {
			// can't determine any scopes
			for permission := range PermissionStrings {
				info.unverifiedPermissions[permission] = struct{}{}
			}
			return info, nil
		}
	} else {
		org = &user.Organization
	}

	// set the organization in the info struct
	info.organization = org

	// read in scopes
	scopesConfig, err := readInScopesConfig()
	if err != nil {
		return nil, err
	}

	// check organization permissions
	organizationPermissions, err := checkOrganizationPermissions(cfg, client, domain, key, scopesConfig, org)
	if err != nil {
		return nil, err
	}

	// check general permissions
	generalOrganizationPermissions, err := checkGeneralPermissions(cfg, client, domain, key, scopesConfig)
	if err != nil {
		return nil, err
	}

	// merge general permissions with organization permissions
	info.orgPermissions = organizationPermissions
	info.orgPermissions = append(info.orgPermissions, generalOrganizationPermissions...)

	// check project permissions
	projectPermissions, err := checkProjectPermissions(cfg, client, domain, key, scopesConfig, org)
	if err != nil {
		return nil, err
	}
	info.projectPermissions = projectPermissions

	return info, nil
}

func checkGeneralPermissions(cfg *config.Config, client *http.Client, domain, key string, scopesConfig *ScopesConfig) ([]Permission, error) {
	return checkPermissions(cfg, client, domain, key, scopesConfig.GeneralScopes)
}

func checkOrganizationPermissions(
	cfg *config.Config,
	client *http.Client,
	domain,
	key string,
	scopesConfig *ScopesConfig,
	org *Organization,
) ([]Permission, error) {
	return checkPermissions(cfg, client, domain, key, scopesConfig.OrganizationScopes, org.ID)
}

func checkProjectPermissions(
	cfg *config.Config,
	client *http.Client,
	domain,
	key string,
	scopesConfig *ScopesConfig,
	org *Organization,
) ([]ProjectPermissions, error) {
	projectPermissions := make([]ProjectPermissions, 0)
	for _, project := range org.Projects {
		projectPermission := ProjectPermissions{
			Project: &project,
		}
		permissions, err := checkPermissions(cfg, client, domain, key, scopesConfig.ProjectScopes, project.ID)
		if err != nil {
			return nil, err
		}
		projectPermission.Permissions = permissions
		projectPermissions = append(projectPermissions, projectPermission)
	}
	return projectPermissions, nil
}

type User struct {
	UUID         string       `json:"uuid"`
	FirstName    string       `json:"first_name"`
	LastName     string       `json:"last_name"`
	Email        string       `json:"email"`
	Organization Organization `json:"organization"`
}

type Organization struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Projects []Project `json:"projects"`
}

type Project struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// resolves the domain and user (if permission exists) by calling the /users/@me method for both US and EU domains
// if the response is 200 OK, it means the domain is valid and user:read permission is also there
// if the response is 403 Forbidden, it means the domain is valid but user:read permission is not there
// if the response is 401 Unauthorized, it means the domain is invalid
func resolveDomainAndUser(cfg *config.Config, client *http.Client, key string) (string, *User, error) {

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
			var userInfo User
			if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
				return "", nil, err
			}
			return domain, &userInfo, nil
		case http.StatusForbidden:
			// domain is valid but user permission does not exist
			return domain, nil, nil
		case http.StatusUnauthorized:
			// Key might not be valid of this domain
			// Try the other domain
			continue
		default:
			// unexpected status code
			return "", nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}
	}
	return "", nil, fmt.Errorf("invalid Posthog API key")
}

func getOrganization(cfg *config.Config, client *http.Client, domain string, key string) (*Organization, error) {
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
		var org Organization
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

func printUser(user User) {
	color.Yellow("\n[i] User Info:")
	color.Green("[i] Name: %s %s", user.FirstName, user.LastName)
	color.Green("[i] Email: %s", user.Email)
	color.Green("[i] ID: %s", user.UUID)
}

func printOrganizationPermissions(organization Organization, permissions []Permission) {
	color.Yellow("\n[i] Organization Permissions:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Organization", "Permission"})
	permissionsString := make([]string, len(permissions))
	for i, permission := range permissions {
		permissionsString[i], _ = permission.ToString()
	}
	t.AppendRow(table.Row{
		color.GreenString(organization.Name),
		color.GreenString(strings.Join(permissionsString, "\n")),
	})
	t.Render()
}

func printProjectPermissions(projectPermissions []ProjectPermissions) {
	color.Yellow("\n[i] Project Permissions:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Project", "Permission"})
	for _, projectPermission := range projectPermissions {
		permissionsString := make([]string, len(projectPermission.Permissions))
		for i, permission := range projectPermission.Permissions {
			permissionsString[i], _ = permission.ToString()

		}
		t.AppendRow(table.Row{
			color.GreenString(projectPermission.Project.Name),
			color.GreenString(strings.Join(permissionsString, "\n")),
		})
	}
	t.Render()
}

func printUnverifiedPermissions(permissions map[Permission]struct{}) {
	color.Yellow("\n[i] Unverified Permissions:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Permission"})
	for permission := range permissions {
		permissionStr, _ := permission.ToString()
		t.AppendRow(table.Row{color.YellowString(permissionStr)})
	}
	t.Render()
}
