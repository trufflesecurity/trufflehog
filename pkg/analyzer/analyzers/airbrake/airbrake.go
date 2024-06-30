package airbrake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

type ProjectsJSON struct {
	Projects []struct {
		Name string `json:"name"`
		ID   int    `json:"id"`
	} `json:"projects"`
}

// validateKey checks if the key is valid and returns the projects associated with the key
func validateKey(cfg *config.Config, key string) (bool, ProjectsJSON, error) {
	// create struct to hold response
	var projects ProjectsJSON

	// create http client
	client := analyzers.NewAnalyzeClient(cfg)

	// create request
	req, err := http.NewRequest("GET", "https://api.airbrake.io/api/v4/projects", nil)
	if err != nil {
		return false, projects, err
	}

	// add key as url param
	q := req.URL.Query()
	q.Add("key", key)
	req.URL.RawQuery = q.Encode()

	// send request
	resp, err := client.Do(req)
	if err != nil {
		return false, projects, err
	}

	// read response
	defer resp.Body.Close()

	// if status code is 200, decode response
	if resp.StatusCode == 200 {
		err := json.NewDecoder(resp.Body).Decode(&projects)
		return true, projects, err
	}

	// if status code is not 200, return false
	return false, projects, nil
}

func AnalyzePermissions(cfg *config.Config, key string) {
	// validate key
	valid, projects, err := validateKey(cfg, key)
	if err != nil {
		color.Red("[x]" + err.Error())
		return
	}

	if !valid {
		color.Red("[x] Invalid Airbrake User API Key")
		return
	}

	color.Green("[!] Valid Airbrake User API Key\n\n")

	if len(key) == 40 {
		color.Green("[i] Key Type: User Key")
		color.Green("[i] Expiration: Never")
	} else {
		color.Yellow("[i] Key Type: User Token")
		color.Yellow("[i] Duration: Short-Lived")
		// ToDo: determine how long these are valid for
	}

	// if key is valid, print projects
	if valid {
		color.Green("\n[i] Projects:")
		printProjects(projects)
	}

	color.Green("\n[i] Permissions:")
	printPermissions()
}

func printProjects(projects ProjectsJSON) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Project ID", "Project Name"})
	for _, project := range projects.Projects {
		t.AppendRow([]interface{}{color.GreenString(strconv.Itoa(project.ID)), color.GreenString(project.Name)})
	}
	t.Render()
}

func printPermissions() {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Scope", "Permissions"})
	for s := range scope_order {
		scope := scope_order[s][0]
		permissions := scope_mapping[scope]
		if scope == "Authentication" {
			t.AppendRow([]interface{}{scope, permissions[0]})
			continue
		}
		for i, permission := range permissions {
			if i == 0 {
				t.AppendRow([]interface{}{color.GreenString(scope), color.GreenString(permission)})
			} else {
				t.AppendRow([]interface{}{"", color.GreenString(permission)})
			}
		}
	}
	t.Render()
	fmt.Println("| Ref: https://docs.airbrake.io/docs/devops-tools/api/     |")
	fmt.Println("+------------------------+---------------------------------+")
}
