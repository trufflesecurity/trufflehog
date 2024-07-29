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
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/pb/analyzerpb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzerpb.AnalyzerType { return analyzerpb.AnalyzerType_GitLab }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	_, err := AnalyzePermissions(a.Cfg, credInfo["key"])
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("not implemented")
}

// consider calling /api/v4/metadata to learn about gitlab instance version and whether neterrprises is enabled

// we'll call /api/v4/personal_access_tokens and /api/v4/user and then filter down to scopes.

type AccessTokenJSON struct {
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

func getPersonalAccessToken(cfg *config.Config, key string) (AccessTokenJSON, int, error) {
	var tokens AccessTokenJSON

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://gitlab.com/api/v4/personal_access_tokens/self", nil)
	if err != nil {
		return tokens, -1, err
	}

	req.Header.Set("Private-Token", key)
	resp, err := client.Do(req)
	if err != nil {
		return tokens, resp.StatusCode, err
	}

	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return tokens, resp.StatusCode, err
	}
	return tokens, resp.StatusCode, nil
}

func getAccessibleProjects(cfg *config.Config, key string) ([]ProjectsJSON, error) {
	var projects []ProjectsJSON

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://gitlab.com/api/v4/projects", nil)
	if err != nil {
		return projects, err
	}

	req.Header.Set("Private-Token", key)

	// Add query parameters
	q := req.URL.Query()
	q.Add("min_access_level", "10")
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return projects, err
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return projects, err
	}

	newBody := func() io.ReadCloser {
		return io.NopCloser(bytes.NewReader(bodyBytes))
	}

	if err := json.NewDecoder(newBody()).Decode(&projects); err != nil {
		var e ErrorJSON
		if err := json.NewDecoder(newBody()).Decode(&e); err == nil {
			return projects, fmt.Errorf("Insufficient Scope to query for projects. We need api or read_api permissions.")
		}
		return projects, err
	}
	return projects, nil
}

func getMetadata(cfg *config.Config, key string) (MetadataJSON, error) {
	var metadata MetadataJSON

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://gitlab.com/api/v4/metadata", nil)
	if err != nil {
		return metadata, err
	}

	req.Header.Set("Private-Token", key)
	resp, err := client.Do(req)
	if err != nil {
		return metadata, err
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
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
		if err := json.NewDecoder(newBody()).Decode(&e); err != nil {
			return metadata, err
		}
		return metadata, fmt.Errorf("Insufficient Scope to query for metadata. We need read_user, ai_features, api or read_api permissions.")
	}

	return metadata, nil
}

type SecretInfo struct {
	AccessToken AccessTokenJSON
	Metadata    MetadataJSON
	Projects    []ProjectsJSON
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	// get personal_access_tokens accessible
	token, statusCode, err := getPersonalAccessToken(cfg, key)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("Invalid GitLab Access Token")
	}

	meta, err := getMetadata(cfg, key)
	if err != nil {
		return nil, err
	}

	projects, err := getAccessibleProjects(cfg, key)
	if err != nil {
		return nil, err
	}

	return &SecretInfo{
		AccessToken: token,
		Metadata:    meta,
		Projects:    projects,
	}, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return
	}

	// print token info
	printTokenInfo(info.AccessToken)

	// print gitlab instance metadata
	if info.Metadata.Version != "" {
		printMetadata(info.Metadata)
	}

	// print token permissions
	printTokenPermissions(info.AccessToken)

	// print repos accessible
	if len(info.Projects) > 0 {
		printProjects(info.Projects)
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

func printTokenInfo(token AccessTokenJSON) {
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

func printTokenPermissions(token AccessTokenJSON) {
	color.Green("[i] Token Permissions\n")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Scope", "Access" /* Add more column headers if needed */})
	for _, scope := range token.Scopes {
		t.AppendRow([]any{color.GreenString(scope), color.GreenString(gitlab_scopes[scope])})
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
		t.AppendRow([]any{color.GreenString(project.NameWithNamespace), access})
	}
	t.Render()
}
