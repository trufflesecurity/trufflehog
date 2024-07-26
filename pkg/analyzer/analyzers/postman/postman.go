package postman

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

type UserInfoJSON struct {
	User struct {
		Username   string   `json:"username"`
		Email      string   `json:"email"`
		FullName   string   `json:"fullName"`
		Roles      []string `json:"roles"`
		TeamName   string   `json:"teamName"`
		TeamDomain string   `json:"teamDomain"`
	} `json:"user"`
}

type WorkspaceJSON struct {
	Workspaces []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Type       string `json:"type"`
		Visibility string `json:"visibility"`
	} `json:"workspaces"`
}

func getUserInfo(cfg *config.Config, key string) (UserInfoJSON, error) {
	var me UserInfoJSON

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://api.getpostman.com/me", nil)
	if err != nil {
		return me, err
	}

	req.Header.Add("X-API-Key", key)

	// send request
	resp, err := client.Do(req)
	if err != nil {
		return me, err
	}

	// read response
	defer resp.Body.Close()

	// if status code is 200, decode response
	if resp.StatusCode == 200 {
		err = json.NewDecoder(resp.Body).Decode(&me)
	}
	return me, err
}

func getWorkspaces(cfg *config.Config, key string) (WorkspaceJSON, error) {
	var workspaces WorkspaceJSON

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://api.getpostman.com/workspaces", nil)
	if err != nil {
		return workspaces, err
	}

	req.Header.Add("X-API-Key", key)

	// send request
	resp, err := client.Do(req)
	if err != nil {
		return workspaces, err
	}

	// read response
	defer resp.Body.Close()

	// if status code is 200, decode response
	if resp.StatusCode == 200 {
		err = json.NewDecoder(resp.Body).Decode(&workspaces)
	}
	return workspaces, err
}

type SecretInfo struct {
	User           UserInfoJSON
	Workspace      WorkspaceJSON
	WorkspaceError error
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

	color.Green("[!] Valid Postman API Key")
	printUserInfo(info.User)

	if info.WorkspaceError != nil {
		color.Red("[x] Error Fetching Workspaces: %s", info.WorkspaceError.Error())
	} else if len(info.Workspace.Workspaces) == 0 {
		color.Red("[x] No Workspaces Found")
	} else {
		printWorkspaces(info.Workspace)
	}
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	// validate key & get user info

	me, err := getUserInfo(cfg, key)
	if err != nil {
		return nil, err
	}

	if me.User.Username == "" {
		return nil, fmt.Errorf("Invalid Postman API Key")
	}

	// get workspaces, if there is error user with empty workspaces will be returned
	workspaces, err := getWorkspaces(cfg, key)

	return &SecretInfo{
		User:           me,
		Workspace:      workspaces,
		WorkspaceError: err,
	}, nil
}

func printUserInfo(me UserInfoJSON) {

	color.Yellow("\n[i] User Information")
	color.Green("Username: " + me.User.Username)
	color.Green("Email: " + me.User.Email)
	color.Green("Full Name: " + me.User.FullName)

	color.Yellow("\n[i] Team Information")
	color.Green("Name: " + me.User.TeamName)
	color.Green("Domain: https://" + me.User.TeamDomain + ".postman.co")

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Scope", "Permissions"})

	for _, role := range me.User.Roles {
		t.AppendRow([]interface{}{color.GreenString(role), color.GreenString(roleDescriptions[role])})
	}
	t.Render()
	fmt.Println("Reference: https://learning.postman.com/docs/collaborating-in-postman/roles-and-permissions/#team-roles")
}

func printWorkspaces(workspaces WorkspaceJSON) {
	color.Yellow("[i] Accessible Workspaces")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Workspace Name", "Type", "Visibility", "Link"})
	for _, workspace := range workspaces.Workspaces {
		t.AppendRow([]interface{}{color.GreenString(workspace.Name), color.GreenString(workspace.Type), color.GreenString(workspace.Visibility), color.GreenString("https://go.postman.co/workspaces/" + workspace.ID)})
	}
	t.Render()
}
