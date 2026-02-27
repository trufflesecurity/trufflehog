//go:generate generate_permissions permissions.yaml permissions.go sourcegraph
package sourcegraph

// ToDo: Add support for custom domain

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/fatih/color"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeSourcegraph }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, ok := credInfo["key"]
	if !ok {
		return nil, analyzers.NewAnalysisError(
			"Sourcegraph", "validate_credentials", "config", "", fmt.Errorf("missing key in credInfo"),
		)
	}
	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError(
			"Sourcegraph", "analyze_permissions", "API", "", err,
		)
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	permission := PermissionStrings[UserRead]
	if info.IsSiteAdmin {
		permission = PermissionStrings[SiteAdminFull]
	}
	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeSourcegraph,
		Metadata:     nil,
		Bindings: []analyzers.Binding{
			{
				Resource: analyzers.Resource{
					Name:               info.User.Data.CurrentUser.Username,
					FullyQualifiedName: "sourcegraph/" + info.User.Data.CurrentUser.Email,
					Type:               "user",
					Metadata: map[string]any{
						"created_at": info.User.Data.CurrentUser.CreatedAt,
						"email":      info.User.Data.CurrentUser.Email,
					},
					Parent: nil,
				},
				Permission: analyzers.Permission{
					Value: permission,
				},
			},
		},
	}

	return &result
}

type GraphQLError struct {
	Message string   `json:"message"`
	Path    []string `json:"path"`
}

type GraphQLResponse struct {
	Errors []GraphQLError `json:"errors"`
	Data   interface{}    `json:"data"`
}

type UserInfoJSON struct {
	Data struct {
		CurrentUser struct {
			Username  string `json:"username"`
			Email     string `json:"email"`
			SiteAdmin bool   `json:"siteAdmin"`
			CreatedAt string `json:"createdAt"`
		} `json:"currentUser"`
	} `json:"data"`
}

type SecretInfo struct {
	User        UserInfoJSON
	IsSiteAdmin bool
}

func getUserInfo(cfg *config.Config, key string) (UserInfoJSON, error) {
	var userInfo UserInfoJSON

	// POST request is considered as non-safe and sourcegraph has graphql APIs. They do not change any state.
	// We are using unrestricted client to avoid error for non-safe API request.
	client := analyzers.NewAnalyzeClientUnrestricted(cfg)
	payload := "{\"query\":\"query { currentUser { username, email, siteAdmin, createdAt } }\"}"
	req, err := http.NewRequest("POST", "https://sourcegraph.com/.api/graphql", strings.NewReader(payload))
	if err != nil {
		return userInfo, err
	}

	req.Header.Set("Authorization", "token "+key)

	resp, err := client.Do(req)
	if err != nil {
		return userInfo, err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	if err != nil {
		return userInfo, err
	}
	return userInfo, nil
}

func checkSiteAdmin(cfg *config.Config, key string) (bool, error) {
	query := `
	{
	    "query": "query webhooks($first: Int, $after: String, $kind: ExternalServiceKind) { webhooks(first: $first, after: $after, kind: $kind) { totalCount } }",
	    "variables": {
	        "first": 10,
	        "after": "",
	        "kind": "GITHUB"
	    }
	}`

	// POST request is considered as non-safe and sourcegraph has graphql APIs. They do not change any state.
	// We are using unrestricted client to avoid error for non-safe API request.
	client := analyzers.NewAnalyzeClientUnrestricted(cfg)
	req, err := http.NewRequest("POST", "https://sourcegraph.com/.api/graphql", strings.NewReader(query))
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "token "+key)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer resp.Body.Close()

	var response GraphQLResponse

	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return false, err
	}

	if len(response.Errors) > 0 {
		return false, nil
	}
	return true, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	// ToDo: Add in logging
	if cfg.LoggingEnabled {
		color.Red("[x] Logging is not supported for this analyzer.")
		return
	}

	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error: %s", err.Error())
		return
	}

	color.Green("[!] Valid Sourcegraph Access Token\n\n")
	color.Yellow("[i] Sourcegraph User Information\n")
	color.Green("Username: %s\n", info.User.Data.CurrentUser.Username)
	color.Green("Email: %s\n", info.User.Data.CurrentUser.Email)
	color.Green("Created At: %s\n\n", info.User.Data.CurrentUser.CreatedAt)

	if info.IsSiteAdmin {
		color.Green("[!] Token Permissions: Site Admin")
	} else {
		// This is the default for all access tokens as of 6/11/24
		color.Yellow("[i] Token Permissions: user:full (default)")
	}
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	userInfo, err := getUserInfo(cfg, key)
	if err != nil {
		return nil, err
	}

	if userInfo.Data.CurrentUser.Username == "" {
		return nil, fmt.Errorf("invalid Sourcegraph Access Token")
	}

	isSiteAdmin, err := checkSiteAdmin(cfg, key)
	if err != nil {
		return nil, err
	}

	return &SecretInfo{
		User:        userInfo,
		IsSiteAdmin: isSiteAdmin,
	}, nil
}
