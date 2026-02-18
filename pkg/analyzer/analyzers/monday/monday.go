//go:generate generate_permissions permissions.yaml permissions.go monday
package monday

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

type SecretInfo struct {
	User      Me
	Account   Account
	Resources []MondayResource
}

func (s *SecretInfo) appendResource(resource MondayResource) {
	s.Resources = append(s.Resources, resource)
}

type MondayResource struct {
	ID       string
	Name     string
	Type     string
	MetaData map[string]string
	Parent   *MondayResource
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeMonday
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, exist := credInfo["key"]
	if !exist {
		return nil, analyzers.NewAnalysisError("Monday", "validate_credentials", "config", "", errors.New("key not found in credentials info"))
	}

	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError("Monday", "analyze_permissions", "API", "", err)
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

	color.Green("[!] Valid Monday Personal Access Token\n\n")
	// print user information
	printUser(info.User)
	printResources(info.Resources)

	color.Yellow("\n[i] Expires: Never")
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	// create http client
	client := analyzers.NewAnalyzeClientUnrestricted(cfg)

	var secretInfo = &SecretInfo{}

	// captureMondayData make a query to graphql API of monday to fetch all data and store it in secret info
	if err := captureMondayData(client, key, secretInfo); err != nil {
		return nil, err
	}

	return secretInfo, nil
}

// secretInfoToAnalyzerResult translate secret info to Analyzer Result
func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeMonday,
		Metadata:     map[string]any{},
		Bindings:     make([]analyzers.Binding, 0),
	}

	// extract information from resource to create bindings and append to result bindings
	for _, resource := range info.Resources {
		binding := analyzers.Binding{
			Resource: analyzers.Resource{
				Name:               resource.Name,
				FullyQualifiedName: fmt.Sprintf("%s/%s", resource.Type, resource.ID), // e.g: Board/123
				Type:               resource.Type,
				Metadata:           map[string]any{}, // to avoid panic
			},
			Permission: analyzers.Permission{
				Value: PermissionStrings[FullAccess], // token always has full access
			},
		}

		for key, value := range resource.MetaData {
			binding.Resource.Metadata[key] = value
		}

		result.Bindings = append(result.Bindings, binding)

	}

	return &result
}

// cli print functions
func printUser(user Me) {
	color.Green("\n[i] User Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "Name", "Email", "Title", "Is Admin", "Is Guest"})
	t.AppendRow(table.Row{color.GreenString(user.ID), color.GreenString(user.Name), color.GreenString(user.Email),
		color.GreenString(user.Title), color.GreenString(fmt.Sprintf("%t", user.IsAdmin)), color.GreenString(fmt.Sprintf("%t", user.IsGuest))})
	t.Render()
}

func printResources(resources []MondayResource) {
	color.Green("\n[i] Resources:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Type"})
	for _, resource := range resources {
		t.AppendRow(table.Row{color.GreenString(resource.Name), color.GreenString(resource.Type)})
	}
	t.Render()
}
