//go:generate generate_permissions permissions.yaml permissions.go square

package square

import (
	"encoding/json"
	"errors"
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

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeSquare }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, ok := credInfo["key"]
	if !ok {
		return nil, analyzers.NewAnalysisError("Square", "validate_credentials", "config", "", errors.New("key not found in credentialInfo"))
	}
	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError("Square", "analyze_permissions", "API", "", err)
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}
	result := analyzers.AnalyzerResult{
		AnalyzerType:       analyzers.AnalyzerTypeSquare,
		UnboundedResources: []analyzers.Resource{},
		Metadata: map[string]any{
			"expires_at":  info.Permissions.ExpiresAt,
			"client_id":   info.Permissions.ClientID,
			"merchant_id": info.Permissions.MerchantID,
		},
	}

	bindings, unboundedResources := getBindingsAndUnboundedResources(info.Permissions.Scopes)

	result.Bindings = bindings
	result.UnboundedResources = append(result.UnboundedResources, unboundedResources...)
	result.UnboundedResources = append(result.UnboundedResources, getTeamMembersResources(info.Team)...)

	return &result
}

// Convert given list of team members into resources
func getTeamMembersResources(team TeamJSON) []analyzers.Resource {
	teamMembersResources := make([]analyzers.Resource, len(team.TeamMembers))

	for idx, teamMember := range team.TeamMembers {
		teamMembersResources[idx] = analyzers.Resource{
			Name:               teamMember.FirstName + " " + teamMember.LastName,
			FullyQualifiedName: teamMember.Email,
			Type:               "team_member",
			Metadata: map[string]any{
				"is_owner":   teamMember.IsOwner,
				"created_at": teamMember.CreatedAt,
			},
		}
	}

	return teamMembersResources
}

// Build a list of Bindings and UnboundedResources by referencing the category permissions list and
// checking with the given scopes
func getBindingsAndUnboundedResources(scopes []string) ([]analyzers.Binding, []analyzers.Resource) {
	bindings := []analyzers.Binding{}
	unboundedResources := []analyzers.Resource{}
	for _, permissions_category := range permissions_slice {
		for category, permissions := range permissions_category {
			parentResource := analyzers.Resource{
				Name:               category,
				FullyQualifiedName: category,
				Type:               "category",
				Metadata:           nil,
				Parent:             nil,
			}
			categoryBinding := make([]analyzers.Binding, 0)
			for endpoint, requiredPermissions := range permissions {
				resource := analyzers.Resource{
					Name:               endpoint,
					FullyQualifiedName: endpoint,
					Type:               "endpoint",
					Metadata:           nil,
					Parent:             &parentResource,
				}
				for _, permission := range requiredPermissions {
					if _, ok := StringToPermission[permission]; !ok { // skip unknown permissions
						continue
					}
					if contains(scopes, permission) {
						categoryBinding = append(categoryBinding, analyzers.Binding{
							Resource: resource,
							Permission: analyzers.Permission{
								Value: permission,
							},
						})
					}
				}
			}
			if len(categoryBinding) == 0 {
				unboundedResources = append(unboundedResources, parentResource)
			} else {
				bindings = append(bindings, categoryBinding...)
			}
		}
	}

	return bindings, unboundedResources
}

type TeamJSON struct {
	TeamMembers []struct {
		IsOwner   bool   `json:"is_owner"`
		FirstName string `json:"given_name"`
		LastName  string `json:"family_name"`
		Email     string `json:"email_address"`
		CreatedAt string `json:"created_at"`
	} `json:"team_members"`
}

type PermissionsJSON struct {
	Scopes     []string `json:"scopes"`
	ExpiresAt  string   `json:"expires_at"`
	ClientID   string   `json:"client_id"`
	MerchantID string   `json:"merchant_id"`
}

type SecretInfo struct {
	Permissions PermissionsJSON
	Team        TeamJSON
}

func getPermissions(cfg *config.Config, key string) (PermissionsJSON, error) {
	var permissions PermissionsJSON

	// POST request is considered as non-safe. Square Post request does not change any state.
	// We are using unrestricted client to avoid error for non-safe API request.
	client := analyzers.NewAnalyzeClientUnrestricted(cfg)
	req, err := http.NewRequest("POST", "https://connect.squareup.com/oauth2/token/status", nil)
	if err != nil {
		return permissions, err
	}

	req.Header.Add("Authorization", "Bearer "+key)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Square-Version", "2024-06-04")

	resp, err := client.Do(req)
	if err != nil {
		return permissions, err
	}

	if resp.StatusCode != 200 {
		return permissions, nil
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&permissions)
	if err != nil {
		return permissions, err
	}
	return permissions, nil
}

func getUsers(cfg *config.Config, key string) (TeamJSON, error) {
	var team TeamJSON

	// POST request is considered as non-safe. Square Post request does not change any state.
	// We are using unrestricted client to avoid error for non-safe API request.
	client := analyzers.NewAnalyzeClientUnrestricted(cfg)
	req, err := http.NewRequest("POST", "https://connect.squareup.com/v2/team-members/search", nil)
	if err != nil {
		return team, err
	}

	req.Header.Add("Authorization", "Bearer "+key)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Square-Version", "2024-06-04")

	q := req.URL.Query()
	q.Add("limit", "200")
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return team, err
	}

	if resp.StatusCode != 200 {
		return team, nil
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&team)
	if err != nil {
		return team, err
	}
	return team, nil
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	permissions, err := getPermissions(cfg, key)
	if err != nil {
		return nil, err
	}

	team, err := getUsers(cfg, key)
	if err != nil {
		return nil, err
	}

	return &SecretInfo{
		Permissions: permissions,
		Team:        team,
	}, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	// ToDo: Add in logging
	if cfg.LoggingEnabled {
		color.Red("[x] Logging is not supported for this analyzer.")
		return
	}

	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error: %s", err.Error())
		return
	}

	if info.Permissions.MerchantID == "" {
		color.Red("[x] Invalid Square API Key")
		return
	}
	color.Green("[!] Valid Square API Key\n\n")
	color.Yellow("Merchant ID: %s", info.Permissions.MerchantID)
	color.Yellow("Client ID: %s", info.Permissions.ClientID)
	if info.Permissions.ExpiresAt == "" {
		color.Green("Expires: Never\n\n")
	} else {
		color.Yellow("Expires: %s\n\n", info.Permissions.ExpiresAt)
	}
	printPermissions(info.Permissions.Scopes, cfg.ShowAll)

	printTeamMembers(info.Team)
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func printPermissions(scopes []string, showAll bool) {
	isAccessToken := true
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"API Category", "Accessible Endpoints"})
	for _, permissions_slice := range permissions_slice {
		for category, permissions := range permissions_slice {
			accessibleEndpoints := []string{}
			for endpoint, requiredPermissions := range permissions {
				hasAllPermissions := true
				for _, permission := range requiredPermissions {
					if !contains(scopes, permission) {
						hasAllPermissions = false
						isAccessToken = false
						break
					}
				}
				if hasAllPermissions {
					accessibleEndpoints = append(accessibleEndpoints, endpoint)
				}
			}
			if len(accessibleEndpoints) == 0 {
				t.AppendRow([]interface{}{category, ""})
			} else {
				t.AppendRow([]interface{}{color.GreenString(category), color.GreenString(strings.Join(accessibleEndpoints, ", "))})
			}
		}
	}
	if isAccessToken {
		color.Green("[i] Permissions: Full Access")
	} else {
		color.Yellow("[i] Permissions:")
	}
	if !isAccessToken || showAll {
		t.SetColumnConfigs([]table.ColumnConfig{
			{Number: 2, WidthMax: 100},
		})
		t.Render()
	}
}

func printTeamMembers(team TeamJSON) {
	if len(team.TeamMembers) == 0 {
		color.Red("\n[x] No team members found")
		return
	}
	color.Yellow("\n[i] Team Members (don't imply any permissions)")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"First Name", "Last Name", "Email", "Owner", "Created At"})
	for _, member := range team.TeamMembers {
		t.AppendRow([]interface{}{color.GreenString(member.FirstName), color.GreenString(member.LastName), color.GreenString(member.Email), color.GreenString(strconv.FormatBool(member.IsOwner)), color.GreenString(member.CreatedAt)})
	}
	t.Render()
}
