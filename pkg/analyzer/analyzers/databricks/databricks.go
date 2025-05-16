//go:generate generate_permissions permissions.yaml permissions.go databricks
package databricks

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
	return analyzers.AnalyzerTypeDataBricks
}

func (a Analyzer) Analyze(ctx context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	token, exist := credInfo["token"]
	if !exist {
		return nil, fmt.Errorf("key not found in credential info")
	}

	domain, exist := credInfo["domain"]
	if !exist {
		return nil, fmt.Errorf("domain not found in credential info")
	}

	info, err := AnalyzePermissions(ctx, a.Cfg, domain, token)
	if err != nil {
		return nil, err
	}

	return secretInfoToAnalyzerResult(info), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, domain, token string) {
	ctx := context.Background()

	info, err := AnalyzePermissions(ctx, cfg, domain, token)
	if err != nil {
		// just print the error in cli and continue as a partial success
		color.Red("[x] Error : %s", err.Error())
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[!] Valid DataBricks Access Token\n\n")

	printUserInfo(info.UserInfo)
	printTokenInfo(info.Tokens)
	printPermissions(info.TokenPermissionLevels)

	if len(info.Resources) > 0 {
		printResources(info.Resources)
	}

	color.Yellow("\n[i] Expires: %s", "N/A (Refer to Token Information Table)")
}

func AnalyzePermissions(ctx context.Context, cfg *config.Config, domain, token string) (*SecretInfo, error) {
	client := analyzers.NewAnalyzeClient(cfg)

	var secretInfo = &SecretInfo{}

	if err := captureUserInfo(ctx, client, domain, token, secretInfo); err != nil {
		return nil, err
	}

	if err := captureTokensInfo(ctx, client, domain, token, secretInfo); err != nil {
		return secretInfo, err
	}

	if err := captureTokenPermissions(ctx, client, domain, token, secretInfo); err != nil {
		return secretInfo, err
	}

	// capture resources
	if err := captureDataBricksResources(ctx, client, domain, token, secretInfo); err != nil {
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
		AnalyzerType: analyzers.AnalyzerTypeDataBricks,
		Metadata:     map[string]any{},
		Bindings:     make([]analyzers.Binding, 0),
	}

	// extract information from resource to create bindings and append to result bindings
	for _, resource := range info.Resources {
		binding := analyzers.Binding{
			Resource: analyzers.Resource{
				Name:               resource.Name,
				FullyQualifiedName: fmt.Sprintf("databricks/%s/%s", resource.Type, resource.ID), // e.g: netlify/site/123
				Type:               resource.Type,
				Metadata:           map[string]any{}, // to avoid panic
			},
		}

		for key, value := range resource.Metadata {
			binding.Resource.Metadata[key] = value
		}

		// for each permission add a binding to resource
		for _, perm := range info.TokenPermissionLevels {
			binding.Permission = analyzers.Permission{
				Value: perm,
			}

			result.Bindings = append(result.Bindings, binding)
		}
	}

	return &result
}

// cli print functions
func printUserInfo(user User) {
	color.Yellow("[i] User Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "UserName", "Primary Email"})
	t.AppendRow(table.Row{color.GreenString(user.ID), color.GreenString(user.UserName), color.GreenString(user.PrimaryEmail)})

	t.Render()
}

func printTokenInfo(tokens []Token) {
	color.Yellow("[i] Tokens Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Expiry Time", "Created By", "Last Used At"})
	for _, token := range tokens {
		t.AppendRow(table.Row{color.GreenString(token.Name),
			color.GreenString(token.ExpiryTime), color.GreenString(token.CreatedBy), color.GreenString(token.LastUsedDay)})
	}
	t.Render()
}

func printPermissions(permissions []string) {
	color.Yellow("[i] Token Permission Levels:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Permission Level"})
	for _, permission := range permissions {
		t.AppendRow(table.Row{color.GreenString(permission)})
	}
	t.Render()
}

func printResources(resources []DataBricksResource) {
	color.Yellow("[i] Resources:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Type"})
	for _, resource := range resources {
		t.AppendRow(table.Row{color.GreenString(resource.Name), color.GreenString(resource.Type)})
	}
	t.Render()
}
