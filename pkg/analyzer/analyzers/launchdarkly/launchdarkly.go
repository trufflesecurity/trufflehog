//go:generate generate_permissions permissions.yaml permissions.go launchdarkly
package launchdarkly

import (
	"errors"
	"fmt"
	"os"
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

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeLaunchDarkly
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	// check if the `key` exist in the credentials info
	key, exist := credInfo["key"]
	if !exist {
		return nil, errors.New("key not found in credentials info")
	}

	if isSDKKey(key) {
		return nil, errors.New("sdk keys cannot be analyzed")
	}

	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, err
	}

	return secretInfoToAnalyzerResult(info), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, token string) {
	if isSDKKey(token) {
		color.Yellow("\n[!] The Provided key is an SDK Key. SDK Keys are sensitive but used to configure LaunchDarkly SDKs")
		color.Green("\n[i] Docs: https://launchdarkly.com/docs/home/account/environment/settings#copy-and-reset-sdk-credentials-for-an-environment")

		return
	}

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
		return nil, fmt.Errorf("failed to fetch resources: %v", err)
	}

	return secretInfo, nil
}

// secretInfoToAnalyzerResult translate secret info to Analyzer Result
func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeLaunchDarkly,
		Metadata:     map[string]any{},
		Bindings:     make([]analyzers.Binding, 0),
	}

	// extract information from resource to create bindings and append to result bindings
	for _, resource := range info.Resources {
		binding := analyzers.Binding{
			Resource: *secretInfoResourceToAnalyzerResource(resource),
			Permission: analyzers.Permission{
				Value: getPermissionType(info.User.Token),
			},
		}

		if resource.ParentResource != nil {
			binding.Resource.Parent = secretInfoResourceToAnalyzerResource(*resource.ParentResource)
		}

		result.Bindings = append(result.Bindings, binding)

	}

	return &result
}

// secretInfoResourceToAnalyzerResource translate secret info resource to analyzer resource for binding
func secretInfoResourceToAnalyzerResource(resource Resource) *analyzers.Resource {
	analyzerRes := analyzers.Resource{
		FullyQualifiedName: resource.ID,
		Name:               resource.Name,
		Type:               resource.Type,
		Metadata:           map[string]any{},
	}

	for key, value := range resource.MetaData {
		analyzerRes.Metadata[key] = value
	}

	return &analyzerRes
}

// getPermissionType return what type of permission is assigned to token
func getPermissionType(token Token) string {
	switch {
	case token.Role != "":
		return token.Role
	case token.hasInlineRole():
		return "Inline Policy"
	case token.hasCustomRoles():
		return "Custom Roles"
	default:
		return ""
	}
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
	if !user.Token.hasCustomRoles() {
		return
	}

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

// printPermissionsType print permissions type token has
func printPermissionsType(token Token) {
	// print permission type. It can be either admin, writer, reader or has inline policy or any custom roles assigned
	color.Green("\n[i] Permission Type: %s", getPermissionType(token))
}

func printResources(resources []Resource) {
	// print resources
	color.Green("\n[i] Resources:")
	callerTable := table.NewWriter()
	callerTable.SetOutputMirror(os.Stdout)
	callerTable.AppendHeader(table.Row{"Name", "Type"})
	for _, resource := range resources {
		callerTable.AppendRow(table.Row{color.GreenString(resource.Name), color.GreenString(resource.Type)})
	}
	callerTable.Render()
}

// isSDKKey check if the key provided is an SDK Key or not
func isSDKKey(key string) bool {
	return strings.HasPrefix(key, "sdk-")
}
