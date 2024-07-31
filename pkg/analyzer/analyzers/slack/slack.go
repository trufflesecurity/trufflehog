package slack

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

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
