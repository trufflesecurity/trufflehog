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

// SecretInfo holds information gathered about a Groq API key.
type SecretInfo struct {
	Valid         bool
	Reference     string
	GroqResources []GroqResource
	Permissions   []string
	Misc          map[string]string
}

// GroqResource is a single resource accessible with a Groq API key.
type GroqResource struct {
	ID         string
	Name       string
	Type       string
	Permission string
	Metadata   map[string]string
}

// appendGroqResource appends a resource onto the secret info list.
func (s *SecretInfo) appendGroqResource(resource GroqResource) {
	s.GroqResources = append(s.GroqResources, resource)
}

// updateMetadata sets a metadata key on the resource. Pointer receiver so
// writes persist when callers mutate before appending.
func (g *GroqResource) updateMetadata(key, value string) {
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
		return nil, analyzers.NewAnalysisError(a.Type().String(), analyzers.OperationValidateCredentials, analyzers.ServiceConfig, "", errors.New("key not found in credentials info"),
		)
	}

	secretInfo, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError(a.Type().String(), analyzers.OperationAnalyzePermissions, analyzers.ServiceAPI, "", err,
		)
	}

	return secretInfoToAnalyzerResult(secretInfo), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
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
	client := analyzers.NewAnalyzeClient(cfg)
	secretInfo := &SecretInfo{Valid: true}

	// Models are on every plan and guarantee analyze bindings. Batches and files
	// are paid Developer-tier APIs; when available we surface those resources too,
	// and when the plan denies them we skip without failing the analysis.
	if err := captureModels(client, apiKey, secretInfo); err != nil {
		return nil, err
	}
	if err := captureBatches(client, apiKey, secretInfo); err != nil {
		return nil, err
	}
	if err := captureFiles(client, apiKey, secretInfo); err != nil {
		return nil, err
	}

	return secretInfo, nil
}

// secretInfoToAnalyzerResult translates secret info into Analyzer Result bindings.
// Permissions in the UI come from these bindings; an empty list looks like "no
// permissions" even when the CLI printed Full Access.
func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	fullAccess := analyzers.Permission{Value: PermissionStrings[FullAccess]}
	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeGroq,
		Metadata:     map[string]any{"Valid_Key": info.Valid},
		// Cap only — length 0 so append does not leave zero-value placeholders.
		Bindings: make([]analyzers.Binding, 0, len(info.GroqResources)),
	}

	for _, groqResource := range info.GroqResources {
		binding := analyzers.Binding{
			Resource: analyzers.Resource{
				Name:               groqResource.Name,
				FullyQualifiedName: groqResource.ID,
				Type:               groqResource.Type,
				Metadata:           map[string]any{},
			},
			Permission: fullAccess,
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
