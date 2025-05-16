//go:generate generate_permissions permissions.yaml permissions.go netlify
package netlify

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
	return analyzers.AnalyzerTypeNetlify
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, exist := credInfo["key"]
	if !exist {
		return nil, fmt.Errorf("key not found in credential info")
	}

	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, err
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

	color.Green("[!] Valid Netlify API key\n\n")

	printUserInfo(info.UserInfo)
	printTokenInfo(info.listResourceByType(Token))
	printResources(info.Resources)

	color.Yellow("\n[i] Expires: %s", "N/A (Refer to Token Information Table)")
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	client := analyzers.NewAnalyzeClient(cfg)

	var secretInfo = &SecretInfo{}

	if err := captureUserInfo(client, key, secretInfo); err != nil {
		return nil, err
	}

	if err := captureTokens(client, key, secretInfo); err != nil {
		return nil, err
	}

	if err := captureResources(client, key, secretInfo); err != nil {
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
		AnalyzerType: analyzers.AnalyzerTypeNetlify,
		Metadata:     map[string]any{},
		Bindings:     make([]analyzers.Binding, 0),
	}

	// extract information from resource to create bindings and append to result bindings
	for _, resource := range info.Resources {
		binding := analyzers.Binding{
			Resource: analyzers.Resource{
				Name:               resource.Name,
				FullyQualifiedName: fmt.Sprintf("netlify/%s/%s", resource.Type, resource.ID), // e.g: netlify/site/123
				Type:               resource.Type,
				Metadata:           map[string]any{}, // to avoid panic
			},
			Permission: analyzers.Permission{
				Value: PermissionStrings[FullAccess], // no fine grain access
			},
		}

		if resource.Parent != nil {
			binding.Resource.Parent = &analyzers.Resource{
				Name:               resource.Parent.Name,
				FullyQualifiedName: resource.Parent.ID,
				Type:               resource.Parent.Type,
				// not copying parent metadata
			}
		}

		for key, value := range resource.Metadata {
			binding.Resource.Metadata[key] = value
		}

		result.Bindings = append(result.Bindings, binding)
	}

	return &result
}

// cli print functions
func printUserInfo(user User) {
	color.Yellow("[i] User Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Email", "Account ID", "Last Login At"})
	t.AppendRow(table.Row{color.GreenString(user.Name), color.GreenString(user.Email), color.GreenString(user.AccountID), color.GreenString(user.LastLogin)})

	t.Render()
}

func printTokenInfo(tokens []NetlifyResource) {
	color.Yellow("[i] Tokens Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "Name", "Personal", "Expires At"})
	for _, token := range tokens {
		t.AppendRow(table.Row{color.GreenString(token.ID), color.GreenString(token.Name), color.GreenString(token.Metadata[tokenPersonal]), color.GreenString(token.Metadata[tokenExpiresAt])})
	}
	t.Render()
}

func printResources(resources []NetlifyResource) {
	color.Yellow("[i] Resources:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Type"})
	for _, resource := range resources {
		// skip token type resource as we will print them separately
		if resource.Type == Token.String() {
			continue
		}

		t.AppendRow(table.Row{color.GreenString(resource.Name), color.GreenString(resource.Type)})
	}
	t.Render()
}
