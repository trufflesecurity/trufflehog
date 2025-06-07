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
	apiKey, exist := credInfo["apiKey"]
	if !exist {
		return nil, errors.New("API key not found in credentials info")
	}

	// Get appKey if provided
	appKey := credInfo["appKey"]

	info, err := AnalyzePermissions(a.Cfg, apiKey, appKey)
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

	color.Green("[i] Valid Datadog API Key\n")

	printUser(info.User)
	printResources(info.Resources)
	printPermissions(info.Permissions)
}

// AnalyzePermissions will collect all the scopes assigned to token along with resource it can access
func AnalyzePermissions(cfg *config.Config, apiKey string, appKey string) (*SecretInfo, error) {
	// create the http client
	client := analyzers.NewAnalyzeClient(cfg)

	var secretInfo = &SecretInfo{}

	// First detect which DataDog domain works with this API key
	baseURL, err := DetectDomain(client, apiKey, appKey)
	if err != nil {
		return nil, fmt.Errorf("[x] %v", err)
	}

	// capture user information in secretInfo
	// If the application key is scoped, user information cannot be retrieved even if all the permissions are granted
	// This is a non-documented Endpoint and can lead to unexpected behavior in future updates
	// If user information is not retrieved, we will move ahead with the rest of the analysis and print the error
	_ = CaptureUserInformation(client, baseURL, apiKey, appKey, secretInfo)

	// capture resources in secretInfo
	if err := CaptureResources(client, baseURL, apiKey, appKey, secretInfo); err != nil {
		return nil, fmt.Errorf("failed to fetch resources: %v", err)
	}

	// capture permissions in secretInfo
	if err := CapturePermissions(client, baseURL, apiKey, appKey, secretInfo); err != nil {
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

	// Create user resource to use as parent
	var userResource *analyzers.Resource
	if info.User.Id != "" {
		userResource = &analyzers.Resource{
			FullyQualifiedName: info.User.Id,
			Name:               info.User.Name,
			Type:               "User",
			Metadata: map[string]any{
				"email": info.User.Email,
			},
		}
	}

	permissionBindings := secretInfoPermissionsToAnalyzerPermission(info.Permissions)
	result.Bindings = analyzers.BindAllPermissions(*userResource, *permissionBindings...)

	// Extract information from resources to create bindings
	for _, resource := range info.Resources {
		resource := secretInfoResourceToAnalyzerResource(resource)

		// Set the user resource as parent if available
		if userResource != nil {
			resource.Parent = userResource
		}

		binding := analyzers.Binding{
			Resource: *resource,
		}

		result.Bindings = append(result.Bindings, binding)
	}

	return &result
}

// secretInfoPermissionsToAnalyzerPermission translate secret info Permission to analyzer resource for binding
func secretInfoPermissionsToAnalyzerPermission(perms []Permission) *[]analyzers.Permission {
	permissions := make([]analyzers.Permission, 0, len(perms))
	for _, perm := range perms {
		permissions = append(permissions, analyzers.Permission{
			Value: perm.Title,
		})
	}
	return &permissions
}

// secretInfoResourceToAnalyzerResource translate secret info Resource to analyzer resource for binding
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
	if user.Id == "" {
		color.Red("\n[x] User information not available")
		return
	}

	color.Green("\n[i] User Information:")
	userTable := table.NewWriter()
	userTable.SetOutputMirror(os.Stdout)
	userTable.AppendHeader(table.Row{"User Id", "Name", "Email"})
	userTable.AppendRow(table.Row{color.GreenString(user.Id), color.GreenString(user.Name), color.GreenString(user.Email)})
	userTable.Render()
}

func printResources(resources []Resource) {
	if len(resources) == 0 {
		color.Red("[x] No resources found")
		return
	}

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
	if len(permissions) == 0 {
		color.Red("[x] No permissions found")
		return
	}

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
