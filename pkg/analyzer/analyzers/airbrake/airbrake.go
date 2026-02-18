package airbrake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

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

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeAirbrake }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	info, err := AnalyzePermissions(a.Cfg, credInfo["key"])
	if err != nil {
		return nil, analyzers.NewAnalysisError(
			"Airbrake", "analyze_permissions", "API", "", err,
		)
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}
	result := analyzers.AnalyzerResult{
		Metadata: map[string]any{
			"key_type":  info.KeyType,
			"reference": info.Reference,
		},
	}
	// Copy the rest of the metadata over.
	for k, v := range info.Misc {
		result.Metadata[k] = v
	}

	// Build a list of Bindings by referencing the same permissions list
	// for each resource.
	permissions := allPermissions()
	for _, proj := range info.Projects {
		resource := analyzers.Resource{
			Name:               proj.Name,
			FullyQualifiedName: strconv.Itoa(proj.ID),
			Type:               "project",
		}
		for _, perm := range permissions {
			binding := analyzers.Binding{
				Resource:   resource,
				Permission: perm,
			}
			result.Bindings = append(result.Bindings, binding)
		}
	}

	return &result
}

type SecretInfo struct {
	KeyType   string
	Projects  []Project
	Reference string
	Scopes    []analyzers.Permission
	Misc      map[string]string
}

type Project struct {
	Name string `json:"name"`
	ID   int    `json:"id"`
}

// validateKey checks if the key is valid and returns the projects associated with the key
func validateKey(cfg *config.Config, key string) (bool, []Project, error) {
	type ProjectsJSON struct {
		Projects []Project `json:"projects"`
	}
	// create struct to hold response
	var projects ProjectsJSON

	// create http client
	client := analyzers.NewAnalyzeClient(cfg)

	// create request
	req, err := http.NewRequest("GET", "https://api.airbrake.io/api/v4/projects", nil)
	if err != nil {
		return false, projects.Projects, err
	}

	// add key as url param
	q := req.URL.Query()
	q.Add("key", key)
	req.URL.RawQuery = q.Encode()

	// send request
	resp, err := client.Do(req)
	if err != nil {
		return false, projects.Projects, err
	}

	// read response
	defer resp.Body.Close()

	// if status code is 200, decode response
	if resp.StatusCode == 200 {
		err := json.NewDecoder(resp.Body).Decode(&projects)
		return true, projects.Projects, err
	}

	// if status code is not 200, return false
	return false, projects.Projects, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] %s", err.Error())
		return
	}

	color.Green("[!] Valid Airbrake User API Key\n\n")
	color.Green("[i] Key Type: " + info.KeyType)
	if v, ok := info.Misc["expiration"]; ok {
		color.Green("[i] Expiration: %s", v)
	}
	if v, ok := info.Misc["duration"]; ok {
		color.Green("[i] Duration: %s", v)
	}

	color.Green("\n[i] Projects:")
	printProjects(info.Projects...)

	color.Green("\n[i] Permissions:")
	printPermissions(info.Scopes)
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	valid, projects, err := validateKey(cfg, key)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf("Invalid Airbrake User API Key")
	}

	info := &SecretInfo{
		Projects:  projects,
		Reference: "https://docs.airbrake.io/docs/devops-tools/api/",
		// If the token exists, it has all permissions.
		Scopes: allPermissions(),
		Misc:   make(map[string]string),
	}
	if len(key) == 40 {
		info.KeyType = "User Key"
		info.Misc["expiration"] = "Never"
	} else {
		info.KeyType = "User Token"
		info.Misc["duration"] = "Short Lived"
	}
	return info, nil
}

func allPermissions() []analyzers.Permission {
	permissions := make([]analyzers.Permission, len(scope_order))
	for i, perm := range scope_order {
		permissions[i] = analyzers.Permission{Value: perm}
	}
	return permissions
}

func printProjects(projects ...Project) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Project ID", "Project Name"})
	for _, project := range projects {
		t.AppendRow([]any{color.GreenString("%d", project.ID), color.GreenString("%s", project.Name)})
	}
	t.Render()
}

func printPermissions(scopes []analyzers.Permission) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Scope", "Permissions"})
	for _, scope := range scopes {
		scope := scope.Value
		for i, permission := range scope_mapping[scope] {
			if i == 0 {
				t.AppendRow([]any{color.GreenString("%s", scope), color.GreenString("%s", permission)})
				continue
			}
		}
	}
	t.Render()
	fmt.Println("| Ref: https://docs.airbrake.io/docs/devops-tools/api/     |")
	fmt.Println("+------------------------+---------------------------------+")
}
