//go:generate generate_permissions permissions.yaml permissions.go datadog
package datadog

import (
	"errors"
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
	return analyzers.AnalyzerTypeDatadog
}

// Analyze performs the analysis of the Datadog API key and returns the analyzer result.
func (a Analyzer) Analyze(ctx context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	// check if the `key` exist in the credentials info
	key, exist := credInfo["key"]
	if !exist {
		return nil, errors.New("key not found in credentials info")
	}

	info, err := AnalyzePermissions(a.Cfg, key, "")
	if err != nil {
		return nil, err
	}

	return secretInfoToAnalyzerResult(info), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, apiKey string, appKey string) {
	info, err := AnalyzePermissions(cfg, apiKey, appKey)
	if err != nil {
		// just print the error in cli and continue as a partial success
		color.Red("[x] Error : %s", err.Error())
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[i] Valid Datadog Token\n")

	printUser(info.User)
	printResources(info.Resources)
	printPermissions(info.Permissions)

	color.Yellow("\n[!] Expires: Never")
}

// AnalyzePermissions will collect all the scopes assigned to token along with resource it can access
func AnalyzePermissions(cfg *config.Config, apiKey string, appKey string) (*SecretInfo, error) {
	// create the http client
	client := analyzers.NewAnalyzeClient(cfg)

	var secretInfo = &SecretInfo{}

	// capture user information in secretInfo
	if err := CaptureUserInformation(client, apiKey, appKey, secretInfo); err != nil {
		return nil, fmt.Errorf("failed to fetch current user: %v", err)
	}

	// capture resources in secretInfo
	if err := CaptureResources(client, apiKey, appKey, secretInfo); err != nil {
		return nil, fmt.Errorf("failed to fetch resources: %v", err)
	}

	if err := CapturePermissions(client, apiKey, appKey, secretInfo); err != nil {
		return nil, fmt.Errorf("failed to fetch permissions: %v", err)
	}

	return secretInfo, nil
}

// secretInfoToAnalyzerResult translate secret info to Analyzer Result
func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeDatadog,
		Metadata:     map[string]any{},
		Bindings:     make([]analyzers.Binding, 0),
	}

	// Extract information from resources to create bindings
	for _, resource := range info.Resources {
		binding := analyzers.Binding{
			Resource: *secretInfoResourceToAnalyzerResource(resource),
			Permission: analyzers.Permission{
				Value: "admin", // Using admin as default permission level
			},
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

func printUser(user User) {
	color.Green("\n[i] User Information:")
	userTable := table.NewWriter()
	userTable.SetOutputMirror(os.Stdout)
	userTable.AppendHeader(table.Row{"User Id", "Name", "Email"})
	userTable.AppendRow(table.Row{color.GreenString(user.Id), color.GreenString(user.Name), color.GreenString(user.Email)})
	userTable.Render()
}

func printResources(resources []Resource) {
	color.Green("\n[i] Resources:")
	resourceTable := table.NewWriter()
	resourceTable.SetOutputMirror(os.Stdout)
	resourceTable.AppendHeader(table.Row{"Name", "Type"})
	for _, resource := range resources {
		resourceTable.AppendRow(table.Row{
			color.GreenString(resource.Name),
			color.GreenString(resource.Type),
		})
	}
	resourceTable.Render()
}

func printPermissions(permissions []Permission) {
	color.Green("\n[i] Permissions:")
	permissionTable := table.NewWriter()
	permissionTable.SetOutputMirror(os.Stdout)
	permissionTable.AppendHeader(table.Row{"Title", "Name", "Description"})

	// Set wrapping for long descriptions
	permissionTable.SetColumnConfigs([]table.ColumnConfig{
		{Number: 3, WidthMax: 50},
	})

	for _, permission := range permissions {
		permissionTable.AppendRow(table.Row{
			color.GreenString(permission.Title),
			color.GreenString(permission.Name),
			color.GreenString(permission.Description),
		})
	}
	permissionTable.Render()
}
