//go:generate generate_permissions permissions.yaml permissions.go asana
package asana

// ToDo: Add OAuth token support.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeAsana }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, ok := credInfo["key"]
	if !ok {
		return nil, errors.New("key not found in credInfo")
	}

	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, err
	}

	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{}

	// resources/permission setup
	permissions := allPermissions()
	userResource := analyzers.Resource{
		Name:               info.Data.Name,
		FullyQualifiedName: info.Data.ID,
		Type:               "user",
		Metadata: map[string]any{
			"email": info.Data.Email,
			"type":  info.Data.Type,
		},
	}

	// bindings to all permissions to resources
	bindings := analyzers.BindAllPermissions(userResource, permissions...)
	result.Bindings = append(result.Bindings, bindings...)

	// unbounded resources
	result.UnboundedResources = make([]analyzers.Resource, 0, len(info.Data.Workspaces))
	for _, workspace := range info.Data.Workspaces {
		resource := analyzers.Resource{
			Name:               workspace.Name,
			FullyQualifiedName: workspace.ID,
			Type:               "workspace",
		}
		result.UnboundedResources = append(result.UnboundedResources, resource)
	}

	return &result
}

type SecretInfo struct {
	Data struct {
		ID         string `json:"gid"`
		Email      string `json:"email"`
		Name       string `json:"name"`
		Type       string `json:"resource_type"`
		Workspaces []struct {
			ID   string `json:"gid"`
			Name string `json:"name"`
		} `json:"workspaces"`
	} `json:"data"`
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	me, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] %s", err.Error())
		return
	}
	printMetadata(me)
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	var me SecretInfo

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://app.asana.com/api/1.0/users/me", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Invalid Asana API Key")
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&me)
	if err != nil {
		return nil, err
	}

	if me.Data.Email == "" {
		return nil, fmt.Errorf("Invalid Asana API Key")
	}
	return &me, nil
}

func printMetadata(me *SecretInfo) {
	color.Green("[!] Valid Asana API Key\n\n")
	color.Yellow("[i] User Information")
	color.Yellow("    Name: %s", me.Data.Name)
	color.Yellow("    Email: %s", me.Data.Email)
	color.Yellow("    Type: %s\n\n", me.Data.Type)

	color.Green("[i] Permissions: Full Access\n\n")

	color.Yellow("[i] Accessible Workspaces")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Workspace Name"})
	for _, workspace := range me.Data.Workspaces {
		t.AppendRow(table.Row{color.GreenString(workspace.Name)})
	}
	t.Render()
}

func allPermissions() []analyzers.Permission {
	permissions := make([]analyzers.Permission, 0, len(PermissionStrings))
	for _, permission := range PermissionStrings {
		permissions = append(permissions, analyzers.Permission{
			Value: permission,
		})
	}
	return permissions
}
