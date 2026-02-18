//go:generate generate_permissions permissions.yaml permissions.go fastly
package fastly

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
	return analyzers.AnalyzerTypeFastly
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, exist := credInfo["key"]
	if !exist {
		return nil, analyzers.NewAnalysisError(
			"Fastly", "validate_credentials", "config", "", fmt.Errorf("key not found in credential info"),
		)
	}

	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError(
			"Fastly", "analyze_permissions", "API", "", err,
		)
	}

	return secretInfoToAnalyzerResult(info), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		// just print the error in cli and continue as a partial success
		color.Red("[x] Error : %s", err.Error())
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[!] Valid Fastly API key\n\n")

	if info.TokenInfo.hasGlobalScope() {
		printUserInfo(info.UserInfo)
	}

	printScopes(info.TokenInfo.Scopes)

	if len(info.Resources) > 0 {
		printResources(info.Resources)
	}

	color.Yellow("\n[i] Expires: %s", info.TokenInfo.ExpiresAt)
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	// create http client
	client := analyzers.NewAnalyzeClient(cfg)

	var secretInfo = &SecretInfo{}

	// capture the token details
	if err := captureTokenInfo(client, key, secretInfo); err != nil {
		return nil, err
	}

	/*
		Fastly defines four types of permissions. Two of these are related specifically to purging:

		- If a token has either `purge_select` or `purge_all` access, it is limited to calling purge-related APIs only.
		- If a token has `global` or `global:read` access, it can call APIs that retrieve resource and user information.
	*/

	if !secretInfo.TokenInfo.hasGlobalScope() {
		return secretInfo, nil
	}

	// capture the user information
	if err := captureUserInfo(client, key, secretInfo); err != nil {
		return nil, err
	}

	// capture the resources
	if err := captureResources(client, key, secretInfo); err != nil {
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
		AnalyzerType: analyzers.AnalyzerTypeFastly,
		Metadata:     map[string]any{},
		Bindings:     make([]analyzers.Binding, 0),
	}

	// extract information from resource to create bindings and append to result bindings
	for _, resource := range info.Resources {
		binding := analyzers.Binding{
			Resource: *secretInfoResourceToAnalyzerResource(resource),
			Permission: analyzers.Permission{
				Value: info.TokenInfo.Scope,
			},
		}

		if resource.Parent != nil {
			binding.Resource.Parent = secretInfoResourceToAnalyzerResource(*resource.Parent)
		}

		result.Bindings = append(result.Bindings, binding)

	}

	return &result
}

// secretInfoResourceToAnalyzerResource translate secret info resource to analyzer resource for binding
func secretInfoResourceToAnalyzerResource(resource FastlyResource) *analyzers.Resource {
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
func printUserInfo(user User) {
	color.Yellow("[i] User Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "Name", "Login", "Role", "Last Active At"})
	t.AppendRow(table.Row{color.GreenString(user.ID), color.GreenString(user.Name), color.GreenString(user.Login), color.GreenString(user.Role), color.GreenString(user.LastActiveAt)})

	t.Render()
}

func printScopes(scopes []string) {
	color.Yellow("[i] Scopes:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Scopes"})
	for _, scope := range scopes {
		t.AppendRow(table.Row{color.GreenString(scope)})
	}
	t.Render()
}

func printResources(resources []FastlyResource) {
	color.Yellow("[i] Resources:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Type"})
	for _, resource := range resources {
		t.AppendRow(table.Row{color.GreenString(resource.Name), color.GreenString(resource.Type)})
	}

	t.Render()
}
