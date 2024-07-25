package asana

// ToDo: Add OAuth token support.

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

type MeJSON struct {
	Data struct {
		Email      string `json:"email"`
		Name       string `json:"name"`
		Type       string `json:"resource_type"`
		Workspaces []struct {
			Name string `json:"name"`
		} `json:"workspaces"`
	} `json:"data"`
}

func getMetadata(cfg *config.Config, key string) (MeJSON, error) {
	var me MeJSON

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://app.asana.com/api/1.0/users/me", nil)
	if err != nil {
		return me, err
	}

	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return me, err
	}

	if resp.StatusCode != 200 {
		return me, nil
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&me)
	if err != nil {
		return me, err
	}
	return me, nil
}

func AnalyzePermissions(cfg *config.Config, key string) {
	me, err := getMetadata(cfg, key)
	if err != nil {
		color.Red("[x] ", err.Error())
		return
	}
	printMetadata(me)
}

func printMetadata(me MeJSON) {
	if me.Data.Email == "" {
		color.Red("[x] Invalid Asana API Key\n")
		return
	}
	color.Green("[!] Valid Asana API Key\n\n")
	color.Yellow("[i] User Information")
	color.Yellow("    Name: %s", me.Data.Name)
	color.Yellow("    Email: %s", me.Data.Email)
	color.Yellow("    Type: %s\n\n", me.Data.Type)

	color.Green("[i] Permissions: Full Access\n\n")

	color.Yellow("[i] Accessible Workspaces")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Workspace Name"})
	for _, workspace := range me.Data.Workspaces {
		t.AppendRow(table.Row{color.GreenString(workspace.Name)})
	}
	t.Render()
}
