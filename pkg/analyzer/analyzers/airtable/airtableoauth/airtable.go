package airtableoauth

import (
	"errors"

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

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeAirtableOAuth }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	token, ok := credInfo["token"]
	if !ok {
		return nil, analyzers.NewAnalysisError("AirtableOAuth", "validate_credentials", "config", "", errors.New("token not found in credInfo"))
	}

	userInfo, err := common.FetchAirtableUserInfo(token)
	if err != nil {
		return nil, analyzers.NewAnalysisError("AirtableOAuth", "analyze_permissions", "API", "", err)
	}

	var basesInfo *common.AirtableBases
	baseScope := common.PermissionStrings[common.SchemaBasesRead]
	if hasScope(userInfo.Scopes, baseScope) {
		basesInfo, _ = common.FetchAirtableBases(token)
	}

	return common.MapToAnalyzerResult(userInfo, basesInfo), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, token string) {
	userInfo, err := common.FetchAirtableUserInfo(token)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	color.Green("[!] Valid Airtable OAuth2 Access Token\n\n")
	printUserAndPermissions(userInfo)

	baseScope := common.PermissionStrings[common.SchemaBasesRead]
	if hasScope(userInfo.Scopes, baseScope) {
		var basesInfo *common.AirtableBases
		basesInfo, _ = common.FetchAirtableBases(token)
		common.PrintBases(basesInfo)
	}
}

func hasScope(scopes []string, target string) bool {
	for _, scope := range scopes {
		if scope == target {
			return true
		}
	}
	return false
}

func printUserAndPermissions(info *common.AirtableUserInfo) {
	scopeStatusMap := make(map[string]bool)
	for _, scope := range common.PermissionStrings {
		scopeStatusMap[scope] = false
	}
	for _, scope := range info.Scopes {
		scopeStatusMap[scope] = true
	}

	common.PrintUserAndPermissions(info, scopeStatusMap)
}
