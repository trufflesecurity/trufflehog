//go:generate generate_permissions permissions.yaml permissions.go airtable_pat
package airtablepat

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

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

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeAirtablePat }

type AirtableUserInfo struct {
	ID    string  `json:"id"`
	Email *string `json:"email,omitempty"`
}

type AirtableBases struct {
	Bases []struct {
		ID     string  `json:"id"`
		Name   string  `json:"name"`
		Schema *Schema `json:"schema,omitempty"`
	} `json:"bases"`
}

type Schema struct {
	Tables []AirtableEntity `json:"tables"`
}

type AirtableRecordsResponse struct {
	Records []AirtableEntity `json:"records"`
}

type AirtableEntity struct {
	ID string `json:"id"`
}

type ScopeConfig struct {
	Permission    string            `json:"permission"`
	Endpoint      string            `json:"endpoint"`
	Method        string            `json:"method"`
	RequiredIDs   []string          `json:"required_ids"`
	ExpectedError map[string]string `json:"expected_error,omitempty"`
}

type ScopesConfig struct {
	Scopes map[string]ScopeConfig `json:"scopes"`
}

var scopeStatusMap = make(map[string]bool)

//go:embed scopes.json
var scopesConfig []byte

func loadScopesConfig() (ScopesConfig, error) {
	var scopesConfigData ScopesConfig
	if err := json.Unmarshal(scopesConfig, &scopesConfigData); err != nil {
		return ScopesConfig{}, err
	}
	return scopesConfigData, nil
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

	scopeStatusMap[PermissionStrings[UserEmailRead]] = userInfo.Email != nil

	scopes, err := loadScopesConfig()
	if err != nil {
		return nil, err
	}

	var basesInfo *AirtableBases
	basesReadPermission := PermissionStrings[SchemaBasesRead]
	if granted, _ := determineScope(token, scopes.Scopes[basesReadPermission], nil); granted {
		basesInfo, _ = fetchAirtableBases(token)
		determineScopes(token, scopes, basesInfo)
	}

	return mapToAnalyzerResult(userInfo, basesInfo), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, token string) {
	userInfo, err := fetchAirtableUserInfo(token)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}
	scopeStatusMap[PermissionStrings[UserEmailRead]] = userInfo.Email != nil

	scopes, err := loadScopesConfig()
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	var basesInfo *AirtableBases
	basesReadPermission := PermissionStrings[SchemaBasesRead]
	if granted, err := determineScope(token, scopes.Scopes[basesReadPermission], nil); granted {
		if err != nil {
			color.Red("[x] Error : %s", err.Error())
			return
		}
		basesInfo, _ = fetchAirtableBases(token)
		determineScopes(token, scopes, basesInfo)
	}

	color.Green("[!] Valid Airtable Personal Access Token\n\n")

	printUserAndPermissions(userInfo)
	if scopeStatusMap[PermissionStrings[SchemaBasesRead]] {
		printBases(basesInfo)
	}
}

func callAirtableAPI(token string, method string, url string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
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
	resp, err := callAirtableAPI(token, "GET", url)
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
		schema, err := fetchBaseSchema(base.ID, token)
		if err != nil {
			basesInfo.Bases[i].Schema = nil
		} else {
			basesInfo.Bases[i].Schema = schema
		}
	}

	return &basesInfo, nil
}

func fetchBaseSchema(baseId, token string) (*Schema, error) {
	url := fmt.Sprintf("https://api.airtable.com/v0/meta/bases/%s/tables", baseId)
	resp, err := callAirtableAPI(token, "GET", url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch schema for base %s, status: %d", baseId, resp.StatusCode)
	}

	var schema Schema
	if err := json.NewDecoder(resp.Body).Decode(&schema); err != nil {
		return nil, err
	}

	return &schema, nil
}

func fetchAirtableRecords(token string, baseId string, tableId string) ([]AirtableEntity, error) {
	url := fmt.Sprintf("https://api.airtable.com/v0/%s/%s", baseId, tableId)
	resp, err := callAirtableAPI(token, "GET", url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch Airtable records, status: %d", resp.StatusCode)
	}

	var recordsResponse AirtableRecordsResponse
	if err := json.NewDecoder(resp.Body).Decode(&recordsResponse); err != nil {
		return nil, err
	}

	return recordsResponse.Records, nil
}

func determineScopes(token string, scopes ScopesConfig, basesInfo *AirtableBases) {
	if basesInfo != nil && len(basesInfo.Bases) > 0 {
		for _, base := range basesInfo.Bases {
			if base.Schema != nil && len(base.Schema.Tables) > 0 {
				baseId := base.ID

				webhookPermission := PermissionStrings[WebhookManage]
				determineScope(token, scopes.Scopes[webhookPermission], map[string]string{"baseId": baseId})

				blockPermission := PermissionStrings[BlockManage]
				determineScope(token, scopes.Scopes[blockPermission], map[string]string{"baseId": baseId})

				// Verifying scopes that require an existing table
				for _, table := range base.Schema.Tables {
					tableId := table.ID
					basesWritePermission := PermissionStrings[SchemaBasesWrite]
					recordsReadPermission := PermissionStrings[DataRecordsRead]
					recordsWritePermission := PermissionStrings[DataRecordsWrite]
					ids := map[string]string{"baseId": baseId, "tableId": tableId}

					determineScope(token, scopes.Scopes[basesWritePermission], ids)
					determineScope(token, scopes.Scopes[recordsWritePermission], ids)
					if granted, _ := determineScope(token, scopes.Scopes[recordsReadPermission], ids); granted {
						// Verifying scopes that require an existing record and record read permission
						records, err := fetchAirtableRecords(token, baseId, tableId)
						if err != nil || len(records) > 0 {
							commentsReadPermission := PermissionStrings[DataRecordcommentsRead]
							for _, record := range records {
								idsWithRecord := map[string]string{"baseId": baseId, "tableId": tableId, "recordId": record.ID}
								determineScope(token, scopes.Scopes[commentsReadPermission], idsWithRecord)
								break
							}
						}
					}
				}
			}
		}
	}
}

func determineScope(token string, scopeConfig ScopeConfig, ids map[string]string) (bool, error) {
	endpoint := scopeConfig.Endpoint
	if ids != nil {
		for key, value := range ids {
			endpoint = strings.Replace(endpoint, fmt.Sprintf("{%s}", key), value, -1)
		}
	}

	resp, err := callAirtableAPI(token, scopeConfig.Method, endpoint)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		scopeStatusMap[scopeConfig.Permission] = true
		return true, nil
	} else if scopeConfig.ExpectedError != nil {
		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return false, err
		}

		if errorInfo, ok := result["error"].(map[string]interface{}); ok {
			if errorType, ok := errorInfo["type"].(string); ok && errorType == scopeConfig.ExpectedError["type"] {
				scopeStatusMap[scopeConfig.Permission] = false
				return false, nil
			}
		}
	}

	scopeStatusMap[scopeConfig.Permission] = true
	return true, nil
}

func mapToAnalyzerResult(userInfo *AirtableUserInfo, basesInfo *AirtableBases) *analyzers.AnalyzerResult {
	if userInfo == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeAirtablePat,
	}
	var permissions []analyzers.Permission
	for scope, status := range scopeStatusMap {
		if status {
			permissions = append(permissions, analyzers.Permission{Value: scope})
		}
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
	t2.AppendHeader(table.Row{"Scope", "Permission", "Status"})
	for _, scope := range PermissionStrings {
		scope_status := "Could not verify"
		if status, ok := scopeStatusMap[scope]; ok {
			if status {
				scope_status = "Granted"
			} else {
				scope_status = "Denied"
			}
		}
		for i, permission := range scope_mapping[scope] {
			scope_string := ""
			if i == 0 {
				scope_string = scope
			}
			t2.AppendRow(table.Row{color.GreenString(scope_string), color.GreenString(permission), color.GreenString(scope_status)})
			scope_status = ""
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
