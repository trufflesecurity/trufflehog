package airtablepat

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/fatih/color"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/airtable/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeAirtablePat }

var scopeStatusMap = make(map[string]bool)

func getEndpoint(endpoint common.EndpointName) common.Endpoint {
	return common.Endpoints[endpoint]
}

func getEndpointByPermission(scope string) common.Endpoint {
	return common.ScopeEndpointMap[scope]
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	token, ok := credInfo["token"]
	if !ok {
		return nil, errors.New("token not found in credInfo")
	}

	userInfo, err := common.FetchAirtableUserInfo(token)
	if err != nil {
		return nil, err
	}

	scopeStatusMap[common.PermissionStrings[common.UserEmailRead]] = userInfo.Email != nil

	var basesInfo *common.AirtableBases
	if granted, _ := determineScope(token, common.SchemaBasesRead, nil); granted {
		basesInfo, _ = common.FetchAirtableBases(token)
		// If bases are fetched, determine the token scopes
		determineScopes(token, basesInfo)
	}

	return mapToAnalyzerResult(userInfo, basesInfo), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, token string) {
	userInfo, err := common.FetchAirtableUserInfo(token)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	scopeStatusMap[common.PermissionStrings[common.UserEmailRead]] = userInfo.Email != nil

	var basesInfo *common.AirtableBases
	basesReadPermission := common.SchemaBasesRead
	if granted, err := determineScope(token, basesReadPermission, nil); granted {
		if err != nil {
			color.Red("[x] Error : %s", err.Error())
			return
		}
		basesInfo, _ = common.FetchAirtableBases(token)
		determineScopes(token, basesInfo)
	}

	color.Green("[!] Valid Airtable Personal Access Token\n\n")

	common.PrintUserAndPermissions(userInfo, scopeStatusMap)
	if scopeStatusMap[common.PermissionStrings[basesReadPermission]] {
		common.PrintBases(basesInfo)
	}
}

func determineScope(token string, scope common.Permission, ids map[string]string) (bool, error) {
	scopeString := common.PermissionStrings[scope]
	endpoint := getEndpointByPermission(scopeString)
	url := endpoint.URL
	if ids != nil {
		for _, key := range endpoint.RequiredIDs {
			if value, ok := ids[key]; ok {
				url = strings.Replace(url, fmt.Sprintf("{%s}", key), value, -1)
			}
		}
	}

	resp, err := common.CallAirtableAPI(token, endpoint.Method, url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		scopeStatusMap[scopeString] = true
		return true, nil
	} else if endpoint.ExpectedErrorResponse != nil {
		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return false, err
		}

		if errorInfo, ok := result["error"].(map[string]interface{}); ok {
			if errorType, ok := errorInfo["type"].(string); ok && errorType == endpoint.ExpectedErrorResponse.Type {
				scopeStatusMap[scopeString] = false
				return false, nil
			}
		}
	}

	scopeStatusMap[scopeString] = true
	return true, nil
}

func determineScopes(token string, basesInfo *common.AirtableBases) {
	if basesInfo != nil && len(basesInfo.Bases) > 0 {
		for _, base := range basesInfo.Bases {
			if base.Schema != nil && len(base.Schema.Tables) > 0 {
				ids := map[string]string{"baseID": base.ID}
				tableScopesDetermined := false

				// Verify token "webhooks:manage" permission
				determineScope(token, common.WebhookManage, ids)
				// Verify token "block:manage" permission
				determineScope(token, common.BlockManage, ids)

				// Verifying scopes that require an existing table
				for _, table := range base.Schema.Tables {
					ids["tableID"] = table.ID

					if !tableScopesDetermined {
						determineScope(token, common.SchemaBasesWrite, ids)
						determineScope(token, common.DataRecordsWrite, ids)
						tableScopesDetermined = true
					}

					if granted, _ := determineScope(token, common.DataRecordsRead, ids); granted {
						// Verifying scopes that require an existing record and record read permission
						records, err := fetchAirtableRecords(token, base.ID, table.ID)
						if err != nil || len(records) > 0 {
							for _, record := range records {
								ids["recordID"] = record.ID
								determineScope(token, common.DataRecordcommentsRead, ids)
								break
							}
							break
						}
					}
				}
			}
		}
	}
}

func mapToAnalyzerResult(userInfo *common.AirtableUserInfo, basesInfo *common.AirtableBases) *analyzers.AnalyzerResult {
	for scope, status := range scopeStatusMap {
		if status {
			userInfo.Scopes = append(userInfo.Scopes, scope)
		}
	}
	return common.MapToAnalyzerResult(userInfo, basesInfo)
}
