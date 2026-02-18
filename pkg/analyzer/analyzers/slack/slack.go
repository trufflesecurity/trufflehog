//go:generate generate_permissions permissions.yaml permissions.go slack

package slack

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeSlack }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, ok := credInfo["key"]
	if !ok {
		return nil, analyzers.NewAnalysisError("Slack", "validate_credentials", "config", "", errors.New("key not found in credentialInfo"))
	}

	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError("Slack", "analyze_permissions", "API", "", err)
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}
	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeSlack,
		Metadata:     nil,
	}

	resourceType := "user"
	fullyQualifiedName := info.User.TeamId + "/" + info.User.UserId
	if info.User.BotId != "" {
		resourceType = "bot"
		fullyQualifiedName = info.User.BotId
	}
	resource := analyzers.Resource{
		Name:               info.User.User,
		FullyQualifiedName: fullyQualifiedName,
		Type:               resourceType,
		Metadata: map[string]any{
			"url":     info.User.Url,
			"team":    info.User.Team,
			"team_id": info.User.TeamId,
			"scopes":  strings.Split(info.Scopes, ","),
		},
	}

	// extract all permissions
	permissions := extractPermissions(info)

	result.Bindings = analyzers.BindAllPermissions(resource, permissions...)

	return &result
}

func extractPermissions(info *SecretInfo) []analyzers.Permission {
	var permissions []analyzers.Permission

	for _, scope := range strings.Split(info.Scopes, ",") {
		perms, ok := scope_mapping[scope]
		if !ok {
			continue
		}

		for _, perm := range perms {
			if _, ok := StringToPermission[perm]; !ok {
				// not in out generated permissions,
				continue
			}

			permissions = append(permissions, analyzers.Permission{
				Value:  perm,
				Parent: nil,
			})
		}
	}

	return permissions
}

// Add in showAll to printScopes + deal with testing enterprise + add scope details

type SlackUserData struct {
	Ok           bool   `json:"ok"`
	Url          string `json:"url"`
	Team         string `json:"team"`
	User         string `json:"user"`
	TeamId       string `json:"team_id"`
	UserId       string `json:"user_id"`
	BotId        string `json:"bot_id"`
	IsEnterprise bool   `json:"is_enterprise"`
}

type SecretInfo struct {
	Scopes string
	User   SlackUserData
}

func getSlackOAuthScopes(cfg *config.Config, key string) (scopes string, userData SlackUserData, err error) {
	userData = SlackUserData{}
	scopes = ""

	// URL to which the request will be sent
	url := "https://slack.com/api/auth.test"

	// Create a client to send the request
	client := analyzers.NewAnalyzeClient(cfg)

	// Create the request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return scopes, userData, err
	}

	// Add the Authorization header to the request
	req.Header.Add("Authorization", "Bearer "+key)

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return scopes, userData, err
	}
	defer resp.Body.Close() // Close the response body when the function returns

	// print body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return scopes, userData, err
	}

	// Unmarshal the response body into the SlackUserData struct
	if err := json.Unmarshal(body, &userData); err != nil {
		return scopes, userData, err
	}

	// Print all headers received from the server
	scopes = resp.Header.Get("X-Oauth-Scopes")
	return scopes, userData, err
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error: %v", err)
		return
	}

	color.Green("[!] Valid Slack API Key\n\n")
	printIdentityInfo(info.User)
	printScopes(strings.Split(info.Scopes, ","))
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	scopes, userData, err := getSlackOAuthScopes(cfg, key)
	if err != nil {
		return nil, fmt.Errorf("error getting Slack OAuth scopes: %w", err)
	}

	if !userData.Ok {
		return nil, fmt.Errorf("invalid Slack token")
	}

	return &SecretInfo{
		Scopes: scopes,
		User:   userData,
	}, nil
}

func printIdentityInfo(userData SlackUserData) {
	if userData.Url != "" {
		color.Green("URL: %v", userData.Url)
	}
	if userData.Team != "" {
		color.Green("Team: %v", userData.Team)
	}
	if userData.User != "" {
		color.Green("User: %v", userData.User)
	}
	if userData.TeamId != "" {
		color.Green("Team ID: %v", userData.TeamId)
	}
	if userData.UserId != "" {
		color.Green("User ID: %v", userData.UserId)
	}
	if userData.BotId != "" {
		color.Green("Bot ID: %v", userData.BotId)
	}
	fmt.Println("")
	if userData.IsEnterprise {
		color.Green("[!] Slack is Enterprise")
	} else {
		color.Yellow("[-] Slack is not Enterprise")
	}
	fmt.Println("")
}

func printScopes(scopes []string) {
	t := table.NewWriter()
	// if !showAll {
	// 	t.SetOutputMirror(os.Stdout)
	// 	t.AppendHeader(table.Row{"Scopes"})
	// 	for _, scope := range scopes {
	// 		t.AppendRow([]interface{}{color.GreenString(scope)})
	// 	}
	// } else {
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Scope", "Permissions"})
	for _, scope := range scopes {
		perms := scope_mapping[scope]
		if perms == nil {
			t.AppendRow([]interface{}{color.GreenString(scope), color.GreenString("")})
		} else {
			t.AppendRow([]interface{}{color.GreenString(scope), color.GreenString(strings.Join(perms, ", "))})
		}

	}
	//}

	t.Render()

}
