package square

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

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

func getPermissions(cfg *config.Config, key string) (PermissionsJSON, error) {
	var permissions PermissionsJSON

	client := analyzers.NewAnalyzeClient(cfg)
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

	client := analyzers.NewAnalyzeClient(cfg)
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

func AnalyzePermissions(cfg *config.Config, key string) {
	permissions, err := getPermissions(cfg, key)
	if err != nil {
		color.Red("Error: %s", err)
		return
	}

	if permissions.MerchantID == "" {
		color.Red("[x] Invalid Square API Key")
		return
	}
	color.Green("[!] Valid Square API Key\n\n")
	color.Yellow("Merchant ID: %s", permissions.MerchantID)
	color.Yellow("Client ID: %s", permissions.ClientID)
	if permissions.ExpiresAt == "" {
		color.Green("Expires: Never\n\n")
	} else {
		color.Yellow("Expires: %s\n\n", permissions.ExpiresAt)
	}
	printPermissions(permissions.Scopes, cfg.ShowAll)

	team, err := getUsers(cfg, key)
	if err != nil {
		color.Red("Error: %s", err)
		return
	}
	printTeamMembers(team)
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
