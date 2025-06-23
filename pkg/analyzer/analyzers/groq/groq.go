//go:generate generate_permissions permissions.yaml permissions.go groq
package groq

import (
	"errors"
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

// SecretInfo hold the information about the groq key
type SecretInfo struct {
	Valid         bool
	Reference     string
	GroqResources []GroqResource
	Permissions   []string
	Misc          map[string]string
}

// GroqResource is a single groq resource which can be accessed with groq api key
type GroqResource struct {
	ID         string
	Name       string
	Type       string
	Permission string
	Metadata   map[string]string
}

// appendGroqResource append the single groq resource to secretinfo groqresources list
func (s *SecretInfo) appendGroqResource(resource GroqResource) {
	s.GroqResources = append(s.GroqResources, resource)
}

// updateMetadata safely update the metadata of the groq resource
func (g GroqResource) updateMetadata(key, value string) {
	if g.Metadata == nil {
		g.Metadata = map[string]string{}
	}

	g.Metadata[key] = value
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeGroq
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
		color.Red("[x] Invalid Groq API key\n")
		color.Red("[x] Error : %s", err.Error())
		return
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[i] Valid Groq API key\n")
	color.Yellow("\n[i] Permission: Full Access\n")

	if len(info.GroqResources) > 0 {
		printGroqResources(info.GroqResources)
	}

	color.Yellow("\n[!] Expires: Never")
}

func AnalyzePermissions(cfg *config.Config, apiKey string) (*SecretInfo, error) {
	// create a HTTP client
	client := analyzers.NewAnalyzeClient(cfg)

	var secretInfo = &SecretInfo{Valid: true}

	if err := captureBatches(client, apiKey, secretInfo); err != nil {
		return nil, err
	}

	if err := captureFiles(client, apiKey, secretInfo); err != nil {
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
		AnalyzerType: analyzers.AnalyzerTypeGroq,
		Metadata:     map[string]any{"Valid_Key": info.Valid},
		Bindings:     make([]analyzers.Binding, len(info.GroqResources)),
	}

	// extract information to create bindings and append to result bindings
	for _, groqResource := range info.GroqResources {
		binding := analyzers.Binding{
			Resource: analyzers.Resource{
				Name:               groqResource.Name,
				FullyQualifiedName: groqResource.ID,
				Type:               groqResource.Type,
				Metadata:           map[string]any{},
			},
			Permission: analyzers.Permission{
				Value: groqResource.Permission,
			},
		}

		for key, value := range groqResource.Metadata {
			binding.Resource.Metadata[key] = value
		}

		result.Bindings = append(result.Bindings, binding)
	}

	return &result
}

func printGroqResources(resources []GroqResource) {
	color.Green("\n[i] Resources:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Type"})
	for _, resource := range resources {
		t.AppendRow(table.Row{color.GreenString(resource.Name), color.GreenString(resource.Type)})
	}
	t.Render()
}
