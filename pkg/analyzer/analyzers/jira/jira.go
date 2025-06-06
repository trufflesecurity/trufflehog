//go:generate generate_permissions permissions.yaml permissions.go jira

package jira

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"

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
	return analyzers.AnalyzerTypeJira
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	token, exist := credInfo["token"]
	if !exist {
		return nil, fmt.Errorf("token not found in credential info")
	}
	domain, exist := credInfo["domain"]
	if !exist {
		return nil, fmt.Errorf("domain not found in credential info")
	}
	email, exist := credInfo["email"]
	if !exist {
		return nil, fmt.Errorf("email not found in credential info")
	}

	info, err := AnalyzePermissions(a.Cfg, token, domain, email)
	if err != nil {
		return nil, err
	}

	return secretInfoToAnalyzerResult(info), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, domain, email, token string) {
	info, err := AnalyzePermissions(cfg, token, domain, email)
	if err != nil {
		// just print the error in cli and continue as a partial success
		color.Red("[x] Error : %s", err.Error())
	} else {
		color.Green("[!] Valid Jira API token\n\n")
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	printUserInfo(info.UserInfo)
	printPermissions(info.Permissions)
	printResources(info.Resources)
}

func AnalyzePermissions(cfg *config.Config, token, domain, email string) (*SecretInfo, error) {
	// create http client
	client := analyzers.NewAnalyzeClient(cfg)

	var secretInfo = &SecretInfo{}

	// capture the user information
	if err := captureUserInfo(client, token, domain, email, secretInfo); err != nil {
		return nil, err
	}

	body, _, err := capturePermissions(client, domain, email, token)
	if err != nil {
		return secretInfo, fmt.Errorf("failed to check permissions: %w", err)
	}

	var permissionsResp JiraPermissionsResponse
	if err := json.Unmarshal(body, &permissionsResp); err != nil {
		return secretInfo, fmt.Errorf("failed to unmarshal permissions response: %w", err)
	}

	var grantedPermissions []string
	for key, perm := range permissionsResp.Permissions {
		if perm.HavePermission {
			grantedPermissions = append(grantedPermissions, key)
		}
	}
	slices.Sort(grantedPermissions)
	secretInfo.Permissions = grantedPermissions

	// capture the resources
	if err := captureResources(client, domain, email, token, secretInfo, grantedPermissions); err != nil {
		// return secretInfo as well in case of error for partial success
		return secretInfo, err
	}

	return secretInfo, nil
}

// secretInfoToAnalyzerResult translate secret info to Analyzer Result
func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeJira,
		Metadata:     map[string]any{},
		Bindings:     make([]analyzers.Binding, 0),
	}

	for _, resource := range info.Resources {
		for _, perm := range resource.Permissions {
			binding := analyzers.Binding{
				Resource: *secretInfoResourceToAnalyzerResource(resource),
				Permission: analyzers.Permission{
					Value: perm,
				},
			}

			if resource.Parent != nil {
				binding.Resource.Parent = secretInfoResourceToAnalyzerResource(*resource.Parent)
			}

			result.Bindings = append(result.Bindings, binding)
		}
	}

	return &result
}

// secretInfoResourceToAnalyzerResource translate secret info resource to analyzer resource for binding
func secretInfoResourceToAnalyzerResource(resource JiraResource) *analyzers.Resource {
	analyzerRes := analyzers.Resource{
		// make fully qualified name unique
		FullyQualifiedName: resource.Type + "/" + resource.ID,
		Name:               resource.Name,
		Type:               resource.Type,
		Metadata:           map[string]any{},
	}

	for key, value := range resource.Metadata {
		analyzerRes.Metadata[key] = value
	}

	return &analyzerRes
}

// cli print functions
func printUserInfo(user JiraUser) {
	if user.AccountID == "" {
		color.Red("[x] No user information found")
		return
	}
	color.Yellow("[i] User Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "Name", "Account Type", "Email", "Active"})
	t.AppendRow(table.Row{color.GreenString(user.AccountID), color.GreenString(user.DisplayName), color.GreenString(user.AccountType), color.GreenString(user.EmailAddress), color.GreenString(fmt.Sprintf("%t", user.Active))})

	t.Render()
}

func printPermissions(permissions []string) {
	if len(permissions) == 0 {
		color.Red("[x] No permissions found")
		return
	}
	color.Yellow("[i] Permissions:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Permission"})
	for _, scope := range permissions {
		t.AppendRow(table.Row{color.GreenString(scope)})
	}
	t.Render()
}

func printResources(resources []JiraResource) {
	if len(resources) == 0 {
		color.Red("[x] No resources found")
		return
	}
	color.Yellow("[i] Resources:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Type"})
	for _, resource := range resources {
		t.AppendRow(table.Row{color.GreenString(resource.Name), color.GreenString(resource.Type)})
	}

	t.Render()
}
