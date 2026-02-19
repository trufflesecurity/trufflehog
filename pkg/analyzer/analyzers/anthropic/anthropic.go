//go:generate generate_permissions permissions.yaml permissions.go anthropic
package anthropic

import (
	"errors"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

const (
	// Key Types
	APIKey   = "API-Key"
	AdminKey = "Admin-Key"
)

type Analyzer struct {
	Cfg *config.Config
}

// SecretInfo hold the information about the anthropic key
type SecretInfo struct {
	Valid              bool
	Type               string // key type - TODO: Handle Anthropic Admin Keys
	AnthropicResources []AnthropicResource
	Permissions        string // always full_access
	Misc               map[string]string
}

// AnthropicResource is any resource that can be accessed with anthropic key
type AnthropicResource struct {
	ID       string
	Name     string
	Type     string
	Parent   *AnthropicResource
	Metadata map[string]string
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerAnthropic
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, exist := credInfo["key"]
	if !exist {
		return nil, errors.New("key not found in credentials info")
	}

	secretInfo, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, err
	}

	return secretInfoToAnalyzerResult(secretInfo), nil
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

	if info.Valid {
		color.Green("[!] Valid Anthropic %s\n\n", info.Type)
		// no user information
		// print full access permission
		printPermission(info.Permissions)
		// print resources
		printAnthropicResources(info.AnthropicResources)

		color.Yellow("\n[i] Expires: Never")
	}
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	// create a HTTP client
	client := analyzers.NewAnalyzeClient(cfg)

	keyType := getKeyType(key)

	var secretInfo = &SecretInfo{
		Type: keyType,
	}

	switch keyType {
	case APIKey:
		if err := captureAPIKeyResources(client, key, secretInfo); err != nil {
			return nil, err
		}
	case AdminKey:
		if err := captureAdminKeyResources(client, key, secretInfo); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported key type")
	}

	// anthropic key has full access only
	secretInfo.Permissions = PermissionStrings[FullAccess]
	secretInfo.Valid = true

	return secretInfo, nil
}

// secretInfoToAnalyzerResult translate secret info to Analyzer Result
func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerAnthropic,
		Metadata:     map[string]any{"Valid_Key": info.Valid},
		Bindings:     make([]analyzers.Binding, 0, len(info.AnthropicResources)), // pre-allocate with zero length
	}

	// extract information to create bindings and append to result bindings
	for _, Anthropicresource := range info.AnthropicResources {
		binding := analyzers.Binding{
			Resource: analyzers.Resource{
				Name:               Anthropicresource.Name,
				FullyQualifiedName: Anthropicresource.ID,
				Type:               Anthropicresource.Type,
				Metadata:           map[string]any{},
			},
			Permission: analyzers.Permission{
				Value: info.Permissions,
			},
		}

		if Anthropicresource.Parent != nil {
			binding.Resource.Parent = &analyzers.Resource{
				Name:               Anthropicresource.Parent.Name,
				FullyQualifiedName: Anthropicresource.Parent.ID,
				Type:               Anthropicresource.Parent.Type,
			}
		}

		for key, value := range Anthropicresource.Metadata {
			binding.Resource.Metadata[key] = value
		}

		result.Bindings = append(result.Bindings, binding)
	}

	return &result
}

func printPermission(permission string) {
	color.Yellow("[i] Permissions:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Permission"})
	t.AppendRow(table.Row{color.GreenString(permission)})
	t.Render()
}

func printAnthropicResources(resources []AnthropicResource) {
	color.Green("\n[i] Resources:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Resource Type", "Resource ID", "Resource Name"})
	for _, resource := range resources {
		t.AppendRow(table.Row{color.GreenString(resource.Type), color.GreenString(resource.ID), color.GreenString(resource.Name)})
	}
	t.Render()
}

// getKeyType return the type of key
func getKeyType(key string) string {
	if strings.Contains(key, "sk-ant-admin01") {
		return AdminKey
	} else if strings.Contains(key, "sk-ant-api03") {
		return APIKey
	}

	return ""
}
