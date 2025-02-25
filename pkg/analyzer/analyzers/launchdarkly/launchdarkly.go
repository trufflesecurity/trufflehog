package launchdarkly

import (
	"fmt"
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

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeLaunchDarkly
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	return nil, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, token string) {
	info, err := AnalyzePermissions(cfg, token)
	if err != nil {
		// just print the error in cli and continue as a partial success
		color.Red("[x] Error : %s", err.Error())
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[i] Valid LaunchDarkly Token\n")
	printUser(info.User)
	printPermissionsType(info.User.Token)

	color.Yellow("\n[!] Expires: Never")
}

// AnalyzePermissions will collect all the scopes assigned to token along with resource it can access
func AnalyzePermissions(cfg *config.Config, token string) (*SecretInfo, error) {
	// create the http client
	client := analyzers.NewAnalyzeClient(cfg)

	var secretInfo = &SecretInfo{}

	// get caller identity
	if err := FetchUserInformation(client, token, secretInfo); err != nil {
		return nil, fmt.Errorf("failed to fetch caller identity: %v", err)
	}

	return secretInfo, nil
}

// printUser print User information from secret info to cli
func printUser(user User) {
	// print caller information
	color.Green("\n[i] User Information:")
	callerTable := table.NewWriter()
	callerTable.SetOutputMirror(os.Stdout)
	callerTable.AppendHeader(table.Row{"Account ID", "Member ID", "Name", "Email", "Role"})
	callerTable.AppendRow(table.Row{color.GreenString(user.AccountID), color.GreenString(user.MemberID),
		color.GreenString(user.Name), color.GreenString(user.Email), color.GreenString(user.Role)})

	callerTable.Render()

	// print token information
	color.Green("\n[i] Token Information")
	tokenTable := table.NewWriter()
	tokenTable.SetOutputMirror(os.Stdout)

	tokenTable.AppendHeader(table.Row{"ID", "Name", "Role", "Is Service Token", "Default API Version",
		"No of Custom Roles Assigned", "Has Inline Policy"})

	tokenTable.AppendRow(table.Row{color.GreenString(user.Token.ID), color.GreenString(user.Token.Name), color.GreenString(user.Token.Role),
		color.GreenString(fmt.Sprintf("%t", user.Token.IsServiceToken)), color.GreenString(fmt.Sprintf("%d", user.Token.APIVersion)),
		color.GreenString(fmt.Sprintf("%d", len(user.Token.CustomRoles))), color.GreenString(fmt.Sprintf("%t", user.Token.hasInlineRole()))})

	tokenTable.Render()

	// print custom roles information
	if user.Token.hasCustomRoles() {
		// print token information
		color.Green("\n[i] Custom Roles Assigned to Token")
		rolesTable := table.NewWriter()
		rolesTable.SetOutputMirror(os.Stdout)
		rolesTable.AppendHeader(table.Row{"ID", "Key", "Name", "Base Permission", "Assigned to members", "Assigned to teams"})
		for _, customRole := range user.Token.CustomRoles {
			rolesTable.AppendRow(table.Row{color.GreenString(customRole.ID), color.GreenString(customRole.Key), color.GreenString(customRole.Name),
				color.GreenString(customRole.BasePermission), color.GreenString(fmt.Sprintf("%d", customRole.AssignedToMembers)),
				color.GreenString(fmt.Sprintf("%d", customRole.AssignedToTeams))})
		}
		rolesTable.Render()
	}
}

// printPermissionType print type of permission token has
func printPermissionsType(token Token) {
	// print permission type. It can be either admin, writer, reader or has inline policy or any custom roles assigned
	permission := ""

	if token.Role != "" {
		permission = token.Role
	} else if token.hasInlineRole() {
		permission = "Inline Policy"
	} else if token.hasCustomRoles() {
		permission = "Custom Roles"
	}

	color.Green("\n[i] Permission Type: %s", permission)
	policesTable := table.NewWriter()
	policesTable.SetOutputMirror(os.Stdout)
	policesTable.AppendHeader(table.Row{"Resource (* means all)", "Action", "Effect"})
	permissions := GetTokenPermissions(token)
	for resource, actions := range permissions {
		for action, effect := range actions {
			if effect == "allow" {
				policesTable.AppendRow(table.Row{color.GreenString(resource), color.GreenString(action), color.GreenString(effect)})
			} else {
				policesTable.AppendRow(table.Row{color.YellowString(resource), color.YellowString(action), color.YellowString(effect)})
			}
		}
	}

	policesTable.Render()
}

// GetTokenPermissions returns a mapping of allowed and denied actions with resources and effects.
func GetTokenPermissions(token Token) map[string]map[string]string {
	permissions := make(map[string]map[string]string)

	// Process Inline Role
	for _, policy := range token.InlineRole {
		processPolicy(policy, permissions)
	}

	// Process Custom Roles
	for _, role := range token.CustomRoles {
		for _, policy := range role.Polices {
			processPolicy(policy, permissions)
		}
	}

	return permissions
}

// processPolicy updates the permissions map with policy details
func processPolicy(policy Policy, permissions map[string]map[string]string) {
	// Handle allowed actions
	for _, resource := range policy.Resources {
		if _, exists := permissions[resource]; !exists {
			permissions[resource] = make(map[string]string)
		}
		for _, action := range policy.Actions {
			permissions[resource][action] = policy.Effect
		}
		for _, action := range policy.NotActions {
			permissions[resource][action] = policy.Effect
		}
	}

	// Handle denied actions
	for _, resource := range policy.NotResources {
		if _, exists := permissions[resource]; !exists {
			permissions[resource] = make(map[string]string)
		}
		for _, action := range policy.Actions {
			permissions[resource][action] = policy.Effect
		}
		for _, action := range policy.NotActions {
			permissions[resource][action] = policy.Effect
		}
	}
}
