//go:generate generate_permissions permissions.yaml permissions.go launchdarkly
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
	printResources(info.Resources)

	color.Yellow("\n[!] Expires: Never")
}

// AnalyzePermissions will collect all the scopes assigned to token along with resource it can access
func AnalyzePermissions(cfg *config.Config, token string) (*SecretInfo, error) {
	// create the http client
	client := analyzers.NewAnalyzeClient(cfg)

	var secretInfo = &SecretInfo{}

	// capture user information in secretInfo
	if err := CaptureUserInformation(client, token, secretInfo); err != nil {
		return nil, fmt.Errorf("failed to fetch caller identity: %v", err)
	}

	// capture resources in secretInfo
	if err := CaptureResources(client, token, secretInfo); err != nil {
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

// printPermissionsType print permissions type token has
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
}

func printResources(resources []Resource) {
	// print resources
	color.Green("\n[i] Resources:")
	callerTable := table.NewWriter()
	callerTable.SetOutputMirror(os.Stdout)
	callerTable.AppendHeader(table.Row{"ID", "Name", "Type"})
	for _, resource := range resources {
		callerTable.AppendRow(table.Row{color.GreenString(resource.ID), color.GreenString(resource.Name),
			color.GreenString(resource.Type)})
	}
	callerTable.Render()
}
