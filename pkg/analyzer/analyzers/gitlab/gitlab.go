package gitlab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

// consider calling /api/v4/metadata to learn about gitlab instance version and whether neterrprises is enabled

// we'll call /api/v4/personal_access_tokens and /api/v4/user and then filter down to scopes.

type AcessTokenJSON struct {
	Name       string   `json:"name"`
	Revoked    bool     `json:"revoked"`
	CreatedAt  string   `json:"created_at"`
	Scopes     []string `json:"scopes"`
	LastUsedAt string   `json:"last_used_at"`
	ExpiresAt  string   `json:"expires_at"`
}

type ProjectsJSON struct {
	NameWithNamespace string `json:"name_with_namespace"`
	Permissions       struct {
		ProjectAccess struct {
			AccessLevel int `json:"access_level"`
		} `json:"project_access"`
	} `json:"permissions"`
}

type ErrorJSON struct {
	Error string `json:"error"`
	Scope string `json:"scope"`
}

type MetadataJSON struct {
	Version    string `json:"version"`
	Enterprise bool   `json:"enterprise"`
}

func getPersonalAccessToken(cfg *config.Config, key string) (AcessTokenJSON, int, error) {
	var tokens AcessTokenJSON

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://gitlab.com/api/v4/personal_access_tokens/self", nil)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return tokens, -1, err
	}

	req.Header.Set("PRIVATE-TOKEN", key)
	resp, err := client.Do(req)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return tokens, resp.StatusCode, err
	}

	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		color.Red("[x] Error: %s", err)
		return tokens, resp.StatusCode, err
	}
	return tokens, resp.StatusCode, nil
}

func getAccessibleProjects(cfg *config.Config, key string) ([]ProjectsJSON, error) {
	var projects []ProjectsJSON

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://gitlab.com/api/v4/projects", nil)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return projects, err
	}

	req.Header.Set("PRIVATE-TOKEN", key)

	// Add query parameters
	q := req.URL.Query()
	q.Add("min_access_level", "10")
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return projects, err
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading the response body:", err)
		return projects, err
	}

	newBody := func() io.ReadCloser {
		return io.NopCloser(bytes.NewReader(bodyBytes))
	}

	if err := json.NewDecoder(newBody()).Decode(&projects); err != nil {
		var e ErrorJSON
		if err := json.NewDecoder(newBody()).Decode(&e); err == nil {
			color.Red("[x] Insufficient Scope to query for projects. We need api or read_api permissions.\n")
			return projects, nil
		}
		color.Red("[x] Error: %s", err)
		return projects, err
	}
	return projects, nil
}

func getMetadata(cfg *config.Config, key string) (MetadataJSON, error) {
	var metadata MetadataJSON

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://gitlab.com/api/v4/metadata", nil)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return metadata, err
	}

	req.Header.Set("PRIVATE-TOKEN", key)
	resp, err := client.Do(req)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return metadata, err
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading the response body:", err)
		return metadata, err
	}

	newBody := func() io.ReadCloser {
		return io.NopCloser(bytes.NewReader(bodyBytes))
	}

	if err := json.NewDecoder(newBody()).Decode(&metadata); err != nil {
		return metadata, err
	}

	if metadata.Version == "" {
		var e ErrorJSON
		if err := json.NewDecoder(newBody()).Decode(&e); err == nil {
			color.Red("[x] Insufficient Scope to query for metadata. We need read_user, ai_features, api or read_api permissions.\n")
			return metadata, nil
		} else {
			return metadata, err
		}
	}

	return metadata, nil
}

func AnalyzePermissions(cfg *config.Config, key string) {

	// get personal_access_tokens accessible
	token, statusCode, err := getPersonalAccessToken(cfg, key)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return
	}

	if statusCode != 200 {
		color.Red("[x] Invalid GitLab Access Token")
		return
	}

	// print token info
	printTokenInfo(token)

	// get metadata
	metadata, err := getMetadata(cfg, key)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return
	}

	// print gitlab instance metadata
	if metadata.Version != "" {
		printMetadata(metadata)
	}

	// print token permissions
	printTokenPermissions(token)

	// get accessible projects
	projects, err := getAccessibleProjects(cfg, key)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return
	}

	// print repos accessible
	if len(projects) > 0 {
		printProjects(projects)
	}
}

func getRemainingTime(t string) string {
	targetTime, err := time.Parse("2006-01-02", t)
	if err != nil {
		return ""
	}

	// Get the current time
	currentTime := time.Now()

	// Calculate the duration until the target time
	durationUntilTarget := targetTime.Sub(currentTime)
	durationUntilTarget = durationUntilTarget.Truncate(time.Minute)

	// Print the duration
	return fmt.Sprintf("%v", durationUntilTarget)
}

func printTokenInfo(token AcessTokenJSON) {
	color.Green("[!] Valid GitLab Access Token\n\n")
	color.Green("Token Name: %s\n", token.Name)
	color.Green("Created At: %s\n", token.CreatedAt)
	color.Green("Last Used At: %s\n", token.LastUsedAt)
	color.Green("Expires At: %s  (%v remaining)\n\n", token.ExpiresAt, getRemainingTime(token.ExpiresAt))
	if token.Revoked {
		color.Red("Token Revoked: %v\n", token.Revoked)
	}
}

func printMetadata(metadata MetadataJSON) {
	color.Green("[i] GitLab Instance Metadata\n")
	color.Green("Version: %s\n", metadata.Version)
	color.Green("Enterprise: %v\n\n", metadata.Enterprise)
}

func printTokenPermissions(token AcessTokenJSON) {
	color.Green("[i] Token Permissions\n")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Scope", "Access" /* Add more column headers if needed */})
	for _, scope := range token.Scopes {
		t.AppendRow([]interface{}{color.GreenString(scope), color.GreenString(gitlab_scopes[scope])})
	}
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, WidthMax: 100}, // Limit the width of the third column (Description) to 20 characters
	})
	t.Render()
}

func printProjects(projects []ProjectsJSON) {
	color.Green("\n[i] Accessible Projects\n")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Project", "Access Level" /* Add more column headers if needed */})
	for _, project := range projects {
		access := access_level_map[project.Permissions.ProjectAccess.AccessLevel]
		if project.Permissions.ProjectAccess.AccessLevel == 50 {
			access = color.GreenString(access)
		} else if project.Permissions.ProjectAccess.AccessLevel >= 30 {
			access = color.YellowString(access)
		} else {
			access = color.RedString(access)
		}
		t.AppendRow([]interface{}{color.GreenString(project.NameWithNamespace), access})
	}
	t.Render()
}
