//go:generate generate_permissions permissions.yaml permissions.go airtable
package airtable

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

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeAirtable }

type AirtableUserInfo struct {
	ID     string   `json:"id"`
	Email  *string  `json:"email,omitempty"`
	Scopes []string `json:"scopes"`
}

type AirtableBases struct {
	Bases []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"bases"`
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	token, ok := credInfo["token"]
	if !ok {
		return nil, errors.New("token not found in credInfo")
	}

	userInfo, err := fetchAirtableUserInfo(token)
	if err != nil {
		return nil, err
	}

	var basesInfo *AirtableBases
	if hasScope(userInfo.Scopes, PermissionStrings[SchemaBasesRead]) {
		basesInfo, _ = fetchAirtableBases(token)
	}

	return mapToAnalyzerResult(userInfo, basesInfo), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, token string) {
	userInfo, err := fetchAirtableUserInfo(token)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	color.Green("[!] Valid Airtable OAuth2 Access Token\n\n")
	printUserAndPermissions(userInfo)

	if hasScope(userInfo.Scopes, PermissionStrings[SchemaBasesRead]) {
		var basesInfo *AirtableBases
		basesInfo, _ = fetchAirtableBases(token)
		printBases(basesInfo)
	}
}

func fetchAirtableUserInfo(token string) (*AirtableUserInfo, error) {
	url := "https://api.airtable.com/v0/meta/whoami"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch Airtable user info, status: %d", resp.StatusCode)
	}

	var userInfo AirtableUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func fetchAirtableBases(token string) (*AirtableBases, error) {
	url := "https://api.airtable.com/v0/meta/bases"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch Airtable bases, status: %d", resp.StatusCode)
	}

	var basesInfo AirtableBases
	if err := json.NewDecoder(resp.Body).Decode(&basesInfo); err != nil {
		return nil, err
	}

	return &basesInfo, nil
}

func hasScope(scopes []string, target string) bool {
	for _, scope := range scopes {
		if scope == target {
			return true
		}
	}
	return false
}

func mapToAnalyzerResult(userInfo *AirtableUserInfo, basesInfo *AirtableBases) *analyzers.AnalyzerResult {
	if userInfo == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeAirtable,
	}
	var permissions []analyzers.Permission
	for _, scope := range userInfo.Scopes {
		permissions = append(permissions, analyzers.Permission{Value: scope})
	}
	userResource := analyzers.Resource{
		Name:               userInfo.ID,
		FullyQualifiedName: userInfo.ID,
		Type:               "user",
		Metadata:           map[string]any{},
	}

	if userInfo.Email != nil {
		userResource.Metadata["email"] = *userInfo.Email
	}

	result.Bindings = analyzers.BindAllPermissions(userResource, permissions...)

	if basesInfo != nil {
		for _, base := range basesInfo.Bases {
			resource := analyzers.Resource{
				Name:               base.Name,
				FullyQualifiedName: base.ID,
				Type:               "base",
			}
			result.UnboundedResources = append(result.UnboundedResources, resource)
		}
	}

	return &result
}

func printUserAndPermissions(info *AirtableUserInfo) {
	color.Yellow("[i] User:")
	t1 := table.NewWriter()
	email := "N/A"
	if info.Email != nil {
		email = *info.Email
	}
	t1.SetOutputMirror(os.Stdout)
	t1.AppendHeader(table.Row{"ID", "Email"})
	t1.AppendRow(table.Row{color.GreenString(info.ID), color.GreenString(email)})
	t1.SetOutputMirror(os.Stdout)
	t1.Render()

	color.Yellow("\n[i] Scopes:")
	t2 := table.NewWriter()
	t2.SetOutputMirror(os.Stdout)
	t2.AppendHeader(table.Row{"Scope", "Permission"})
	for _, scope := range info.Scopes {
		for i, permission := range scope_mapping[scope] {
			scope_string := ""
			if i == 0 {
				scope_string = scope
			}
			t2.AppendRow(table.Row{color.GreenString(scope_string), color.GreenString(permission)})
		}
	}
	t2.Render()
	fmt.Printf("%s: https://airtable.com/developers/web/api/scopes\n", color.GreenString("Ref"))
}

func printBases(bases *AirtableBases) {
	color.Yellow("\n[i] Bases:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	if len(bases.Bases) > 0 {
		t.AppendHeader(table.Row{"ID", "Name"})
		for _, base := range bases.Bases {
			t.AppendRow(table.Row{color.GreenString(base.ID), color.GreenString(base.Name)})
		}
	} else {
		fmt.Printf("%s\n", color.GreenString("No bases associated with token"))
	}
	t.Render()
}
