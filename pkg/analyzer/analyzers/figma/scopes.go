package figma

import (
	_ "embed"
	"encoding/json"
	"errors"
)

type Scope string

const (
	ScopeFilesRead             Scope = "files:read"
	ScopeFileVariablesRead     Scope = "file_variables:read"
	ScopeFileVariablesWrite    Scope = "file_variables:write"
	ScopeFileCommentsWrite     Scope = "file_comments:write"
	ScopeFileDevResourcesRead  Scope = "file_dev_resources:read"
	ScopeFileDevResourcesWrite Scope = "file_dev_resources:write"
	ScopeLibraryAnalyticsRead  Scope = "library_analytics:read"
	ScopeWebhooksWrite         Scope = "webhooks:write"
)

// This list orders the scope in which they must be tested
var orderedScopeList = []Scope{
	ScopeFilesRead,
	ScopeLibraryAnalyticsRead,
	ScopeFileDevResourcesWrite,
	ScopeFileVariablesRead,
	ScopeWebhooksWrite,
}

var scopeToActions = map[Scope][]string{
	ScopeFilesRead: {
		"Get user info",
		"Read files",
		"Read projects",
		"Read users",
		"Read versions",
		"Read comments",
		"Read components & styles",
		"Read webhooks",
	},
	ScopeFileVariablesRead: {
		"Read file variables",
	},
	ScopeFileVariablesWrite: {
		"Write file variables",
	},
	ScopeFileCommentsWrite: {
		"Post comments",
		"Delete comments",
		"Post comment reactions",
		"Delete comment reactions",
	},
	ScopeFileDevResourcesRead: {
		"Read file dev resources",
	},
	ScopeFileDevResourcesWrite: {
		"Write file dev resources",
	},
	ScopeLibraryAnalyticsRead: {
		"Read design system analytics",
	},
	ScopeWebhooksWrite: {
		"Create webhooks",
		"Manage webhooks",
	},
}

var scopeStringToScope map[string]Scope

//go:embed endpoints.json
var endpointsConfig []byte

func init() {
	scopeStringToScope = map[string]Scope{
		string(ScopeFilesRead):             ScopeFilesRead,
		string(ScopeFileVariablesRead):     ScopeFileVariablesRead,
		string(ScopeFileVariablesWrite):    ScopeFileVariablesWrite,
		string(ScopeFileCommentsWrite):     ScopeFileCommentsWrite,
		string(ScopeFileDevResourcesRead):  ScopeFileDevResourcesRead,
		string(ScopeFileDevResourcesWrite): ScopeFileDevResourcesWrite,
		string(ScopeLibraryAnalyticsRead):  ScopeLibraryAnalyticsRead,
		string(ScopeWebhooksWrite):         ScopeWebhooksWrite,
	}
}

func getScopeActions(scope Scope) []string {
	return scopeToActions[scope]
}

func getScopeEndpointsMap() (map[Scope]endpoint, error) {
	var scopeToEndpoints map[Scope]endpoint
	if err := json.Unmarshal(endpointsConfig, &scopeToEndpoints); err != nil {
		return nil, errors.New("failed to unmarshal endpoints.json: " + err.Error())
	}
	return scopeToEndpoints, nil
}

func getScopeEndpoint(scopeToEndpoint map[Scope]endpoint, scope Scope) (endpoint, error) {
	if endpoint, ok := scopeToEndpoint[scope]; ok {
		return endpoint, nil
	}
	return endpoint{}, errors.New("invalid scope or endpoint doesn't exist")
}

func getScopesFromScopeStrings(scopeStrings []string) []Scope {
	var scopes []Scope
	for _, scopeString := range scopeStrings {
		if scope, ok := scopeStringToScope[scopeString]; ok {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}

func getAllScopes() []Scope {
	return []Scope{
		ScopeFilesRead,
		ScopeFileVariablesRead,
		ScopeFileVariablesWrite,
		ScopeFileCommentsWrite,
		ScopeFileDevResourcesRead,
		ScopeFileDevResourcesWrite,
		ScopeLibraryAnalyticsRead,
		ScopeWebhooksWrite,
	}
}
