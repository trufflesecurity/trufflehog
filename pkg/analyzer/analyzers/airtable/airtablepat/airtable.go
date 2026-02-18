package airtablepat

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
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

func getEndpoint(endpointName common.EndpointName) (common.Endpoint, bool) {
	return common.GetEndpoint(endpointName)
}

func getScopeEndpoint(scope string) (common.Endpoint, bool) {
	return common.GetScopeEndpoint(scope)
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	token, ok := credInfo["token"]
	if !ok {
		return nil, analyzers.NewAnalysisError("AirtablePat", "validate_credentials", "config", "", errors.New("token not found in credInfo"))
	}

	userInfo, err := common.FetchAirtableUserInfo(token)
	if err != nil {
		return nil, analyzers.NewAnalysisError("AirtablePat", "analyze_permissions", "API", "", err)
	}

	scopeStatusMap[common.PermissionStrings[common.UserEmailRead]] = userInfo.Email != nil

	var basesInfo *common.AirtableBases
	granted, err := determineScope(token, common.SchemaBasesRead, nil)
	if err != nil {
		return nil, analyzers.NewAnalysisError("AirtablePat", "analyze_permissions", "API", "", err)
	}
	if granted {
		basesInfo, err = common.FetchAirtableBases(token)
		if err != nil {
			return nil, analyzers.NewAnalysisError("AirtablePat", "analyze_permissions", "API", "", err)
		}
		// If bases are fetched, determine the token scopes
		err := determineScopes(token, basesInfo)
		if err != nil {
			return nil, analyzers.NewAnalysisError("AirtablePat", "analyze_permissions", "API", "", err)
		}
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
		err := determineScopes(token, basesInfo)
		if err != nil {
			color.Red("[x] Error : %s", err.Error())
			return
		}
	}

	color.Green("[!] Valid Airtable Personal Access Token\n\n")

	common.PrintUserAndPermissions(userInfo, scopeStatusMap)
	if scopeStatusMap[common.PermissionStrings[basesReadPermission]] {
		common.PrintBases(basesInfo)
	}
}

// determineScope checks whether the given token has the specified permission by making an API call.
//
// The function performs the following actions:
//   - Determines the appropriate API Endpoint based on the input scope/permission.
//   - Constructs an HTTP request using the endpoint's URL, method, and required IDs.
//     If the URL contains path parameters (e.g., "{baseID}"), they must be replaced using `requiredIDs`.
//   - Sends the request and analyzes the response to determine if the token has the requested permission.
//
// Returns `true` if the token has the permission, `false` otherwise.
// If an error occurs, it returns false along with the encountered error.
func determineScope(token string, perm common.Permission, requiredIDs map[string]string) (bool, error) {
	scopeString := common.PermissionStrings[perm]
	endpoint, exists := getScopeEndpoint(scopeString)
	if !exists {
		return false, nil
	}

	url := endpoint.URL
	if requiredIDs != nil {
		for _, key := range endpoint.RequiredIDs {
			if value, ok := requiredIDs[key]; ok {
				url = strings.Replace(url, fmt.Sprintf("{%s}", key), value, -1)
			}
		}
	}

	resp, err := common.CallAirtableAPI(token, endpoint.Method, url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == endpoint.ExpectedSuccessStatus {
		scopeStatusMap[scopeString] = true
		return true, nil
	}

	// If the response status is not 200 OK, we need to verify if the error is as expected
	if endpoint.ExpectedErrorResponse != nil {
		var result map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return false, err
		}

		errorInfo, ok := result["error"].(map[string]any)
		if !ok {
			// If no error is found in the response, the scope is unverified
			return false, nil
		}
		errorType, ok := errorInfo["type"].(string)
		if !ok || errorType != endpoint.ExpectedErrorResponse.Type {
			// If "type" is missing from the error body, or mismatches the expected type, the scope is unverified
			return false, nil
		}

		// The token lacks the scope/permission to fulfill the request
		scopeStatusMap[scopeString] = false
		return false, nil
	}

	// Can not determine scope as the expected error is unknown
	return false, nil
}

func determineScopes(token string, basesInfo *common.AirtableBases) error {
	if basesInfo == nil || len(basesInfo.Bases) == 0 {
		return nil
	}

	for _, base := range basesInfo.Bases {
		requiredIDs := map[string]string{"baseID": base.ID}
		tableScopesDetermined := false

		// Verify token "webhooks:manage" permission
		_, err := determineScope(token, common.WebhookManage, requiredIDs)
		if err != nil {
			return err
		}
		// Verify token "block:manage" permission
		_, err = determineScope(token, common.BlockManage, requiredIDs)
		if err != nil {
			return err
		}

		if base.Schema == nil || len(base.Schema.Tables) == 0 {
			return nil
		}

		// Verifying scopes that require an existing table
		for _, table := range base.Schema.Tables {
			requiredIDs["tableID"] = table.ID

			if !tableScopesDetermined {
				_, err = determineScope(token, common.SchemaBasesWrite, requiredIDs)
				if err != nil {
					return err
				}
				_, err = determineScope(token, common.DataRecordsWrite, requiredIDs)
				if err != nil {
					return err
				}
				tableScopesDetermined = true
			}

			granted, err := determineScope(token, common.DataRecordsRead, requiredIDs)
			if err != nil {
				return err
			}
			if !granted {
				continue
			}
			// Verifying scopes that require an existing "record" and the "data records read" permission
			records, err := fetchAirtableRecords(token, base.ID, table.ID)
			if err != nil {
				return err
			}
			for _, record := range records {
				requiredIDs["recordID"] = record.ID
				_, err = determineScope(token, common.DataRecordcommentsRead, requiredIDs)
				if err != nil {
					return err
				}
				break
			}
			if len(records) != 0 {
				break
			}
		}
	}
	return nil
}

func mapToAnalyzerResult(userInfo *common.AirtableUserInfo, basesInfo *common.AirtableBases) *analyzers.AnalyzerResult {
	for scope, status := range scopeStatusMap {
		if status {
			userInfo.Scopes = append(userInfo.Scopes, scope)
		}
	}
	return common.MapToAnalyzerResult(userInfo, basesInfo)
}
