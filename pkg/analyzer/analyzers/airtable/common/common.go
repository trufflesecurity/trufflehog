//go:generate generate_permissions permissions.yaml permissions.go common
package common

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

func CallAirtableAPI(token string, method string, url string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := detectors.DetectorHttpClientWithNoLocalAddresses.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func FetchAirtableUserInfo(token string) (*AirtableUserInfo, error) {
	endpoint, exists := GetEndpoint(GetUserInfoEndpoint)
	if !exists {
		return nil, fmt.Errorf("endpoint for GetUserInfoEndpoint does not exist")
	}
	resp, err := CallAirtableAPI(token, endpoint.Method, endpoint.URL)
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

func FetchAirtableBases(token string) (*AirtableBases, error) {
	endpoint, exists := GetEndpoint(ListBasesEndpoint)
	if !exists {
		return nil, fmt.Errorf("endpoint for ListBasesEndpoint does not exist")
	}
	resp, err := CallAirtableAPI(token, endpoint.Method, endpoint.URL)
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

	// Fetch schema for each base
	for i, base := range basesInfo.Bases {
		schema, err := fetchBaseSchema(token, base.ID)
		if err != nil {
			basesInfo.Bases[i].Schema = nil
		} else {
			basesInfo.Bases[i].Schema = schema
		}
	}

	return &basesInfo, nil
}

func fetchBaseSchema(token string, baseID string) (*Schema, error) {
	endpoint, exists := GetEndpoint(GetBaseSchemaEndpoint)
	if !exists {
		return nil, fmt.Errorf("endpoint for GetBaseSchemaEndpoint does not exist")
	}
	url := strings.Replace(endpoint.URL, "{baseID}", baseID, -1)
	resp, err := CallAirtableAPI(token, endpoint.Method, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch schema for base %s, status: %d", baseID, resp.StatusCode)
	}

	var schema Schema
	if err := json.NewDecoder(resp.Body).Decode(&schema); err != nil {
		return nil, err
	}

	return &schema, nil
}

func MapToAnalyzerResult(userInfo *AirtableUserInfo, basesInfo *AirtableBases) *analyzers.AnalyzerResult {
	if userInfo == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeAirtableOAuth,
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

func PrintUserAndPermissions(info *AirtableUserInfo, scopeStatusMap map[string]bool) {
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
	t2.AppendHeader(table.Row{"Scope", "Permission", "Status"})
	for _, scope := range PermissionStrings {
		scopeStatus := "Could not verify"
		if status, ok := scopeStatusMap[scope]; ok {
			if status {
				scopeStatus = "Granted"
			} else {
				scopeStatus = "Denied"
			}
		}
		permissions, ok := GetScopePermissions(scope)
		if !ok {
			continue
		}
		for i, permission := range permissions {
			scopeString := ""
			if i == 0 {
				scopeString = scope
			}
			t2.AppendRow(table.Row{color.GreenString(scopeString), color.GreenString(permission), color.GreenString(scopeStatus)})
			scopeStatus = ""
		}
		t2.AppendSeparator()
	}
	t2.Render()
	fmt.Printf("%s: https://airtable.com/developers/web/api/scopes\n", color.GreenString("Ref"))
}

func PrintBases(bases *AirtableBases) {
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
