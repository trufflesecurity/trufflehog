//go:generate generate_permissions permissions.yaml permissions.go bitbucket
package bitbucket

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

var resource_name_map = map[string]string{
	"repo_access_token":      "Repository",
	"project_access_token":   "Project",
	"workspace_access_token": "Workspace",
}

type SecretInfo struct {
	Type        string
	OauthScopes []string
	Repos       []Repo
}

type Repo struct {
	ID       string `json:"uuid"`
	FullName string `json:"full_name"`
	RepoName string `json:"name"`
	Project  struct {
		ID   string `json:"uuid"`
		Name string `json:"name"`
	} `json:"project"`
	Workspace struct {
		ID   string `json:"uuid"`
		Name string `json:"name"`
	} `json:"workspace"`
	IsPrivate bool `json:"is_private"`
	Owner     struct {
		ID       string `json:"uuid"`
		Username string `json:"username"`
	} `json:"owner"`
	Role string
}

type RepoJSON struct {
	Values []Repo `json:"values"`
}

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeBitbucket }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, ok := credInfo["key"]
	if !ok {
		return nil, analyzers.NewAnalysisError("Bitbucket", "validate_credentials", "config", "", errors.New("key not found in credentialInfo"))
	}
	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError("Bitbucket", "analyze_permissions", "API", "", err)
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeBitbucket,
	}

	// add unbounded resources
	result.UnboundedResources = make([]analyzers.Resource, len(info.Repos))
	for i, repo := range info.Repos {
		result.UnboundedResources[i] = analyzers.Resource{
			Type:               "repository",
			Name:               repo.FullName,
			FullyQualifiedName: "bitbucket.com/repository/" + repo.ID,
			Parent: &analyzers.Resource{
				Type:               "project",
				Name:               repo.Project.Name,
				FullyQualifiedName: "bitbucket.com/project/" + repo.Project.ID,
				Parent: &analyzers.Resource{
					Type:               "workspace",
					Name:               repo.Workspace.Name,
					FullyQualifiedName: "bitbucket.com/workspace/" + repo.Workspace.ID,
				},
			},
			Metadata: map[string]any{
				"owner_id":   repo.Owner.ID,
				"owner":      repo.Owner.Username,
				"is_private": repo.IsPrivate,
				"role":       repo.Role,
			},
		}
	}

	credentialResource := &analyzers.Resource{
		Type:               info.Type,
		Name:               resource_name_map[info.Type],
		FullyQualifiedName: "bitbucket.com/credential/" + info.Type,
		Metadata: map[string]any{
			"type": credential_type_map[info.Type],
		},
	}

	for _, scope := range info.OauthScopes {
		result.Bindings = append(result.Bindings, analyzers.Binding{
			Resource: *credentialResource,
			Permission: analyzers.Permission{
				Value: scope,
			},
		})
	}

	return &result
}

func getScopesAndType(cfg *config.Config, key string) (string, []string, error) {
	// client
	client := analyzers.NewAnalyzeClient(cfg)

	// request
	req, err := http.NewRequest("GET", "https://api.bitbucket.org/2.0/repositories", nil)
	if err != nil {
		return "", nil, err
	}

	// headers
	req.Header.Set("Authorization", "Bearer "+key)

	// response
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	// parse response headers
	credentialType := resp.Header.Get("x-credential-type")
	oauthScopes := resp.Header.Get("x-oauth-scopes")

	scopes := strings.Split(oauthScopes, ", ")
	return credentialType, scopes, nil
}

func scopesToBitbucketScopes(scopes ...analyzers.Permission) []BitbucketScope {
	scopesSlice := []BitbucketScope{}
	for _, scope := range scopes {
		scope := scope.Value
		mapping := oauth_scope_map[scope]
		for _, impliedScope := range mapping.ImpliedScopes {
			scopesSlice = append(scopesSlice, oauth_scope_map[impliedScope])
		}
		scopesSlice = append(scopesSlice, oauth_scope_map[scope])
	}

	// sort scopes by category
	sort.Sort(ByCategoryAndName(scopesSlice))
	return scopesSlice
}

func getRepositories(cfg *config.Config, key string, role string) (RepoJSON, error) {
	var repos RepoJSON

	// client
	client := analyzers.NewAnalyzeClient(cfg)

	// request
	req, err := http.NewRequest("GET", "https://api.bitbucket.org/2.0/repositories", nil)
	if err != nil {
		return repos, err
	}

	// headers
	req.Header.Set("Authorization", "Bearer "+key)

	// add query params
	q := req.URL.Query()
	q.Add("role", role)
	q.Add("pagelen", "100")
	req.URL.RawQuery = q.Encode()

	// response
	resp, err := client.Do(req)
	if err != nil {
		return repos, err
	}
	defer resp.Body.Close()

	// parse response body
	err = json.NewDecoder(resp.Body).Decode(&repos)
	if err != nil {
		return repos, err
	}

	return repos, nil
}

func getAllRepos(cfg *config.Config, key string) ([]Repo, error) {
	roles := []string{"member", "contributor", "admin", "owner"}

	var allRepos = make(map[string]Repo, 0)
	for _, role := range roles {
		repos, err := getRepositories(cfg, key, role)
		if err != nil {
			return nil, err
		}
		// purposefully overwriting, so that get the most permissive role
		for _, repo := range repos.Values {
			repo.Role = role
			allRepos[repo.FullName] = repo
		}
	}
	repoSlice := make([]Repo, 0, len(allRepos))
	for _, repo := range allRepos {
		repoSlice = append(repoSlice, repo)
	}
	return repoSlice, nil
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	credentialType, oauthScopes, err := getScopesAndType(cfg, key)
	if err != nil {
		return nil, err
	}

	// get all repos available to user
	// ToDo: pagination
	repos, err := getAllRepos(cfg, key)
	if err != nil {
		return nil, err
	}
	return &SecretInfo{
		Type:        credentialType,
		OauthScopes: oauthScopes,
		Repos:       repos,
	}, nil
}

func convertScopeToAnalyzerPermissions(scopes []string) []analyzers.Permission {
	permissions := make([]analyzers.Permission, 0, len(scopes))
	for _, scope := range scopes {
		permissions = append(permissions, analyzers.Permission{Value: scope})
	}
	return permissions
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error: %s", err.Error())
		return
	}
	printScopes(info.Type, convertScopeToAnalyzerPermissions(info.OauthScopes))
	printAccessibleRepositories(info.Repos)
}

func printScopes(credentialType string, scopes []analyzers.Permission) {
	if credentialType == "" {
		color.Red("[x] Invalid Bitbucket access token.")
		return
	}
	color.Green("[!] Valid Bitbucket access token.\n\n")
	color.Green("[i] Credential Type: %s\n\n", credential_type_map[credentialType])

	color.Yellow("[i] Access Token Scopes:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Category", "Permission"})

	currentCategory := ""
	for _, scope := range scopesToBitbucketScopes(scopes...) {
		if currentCategory != scope.Category {
			currentCategory = scope.Category
			t.AppendRow([]any{scope.Category, ""})
		}
		t.AppendRow([]any{"", color.GreenString(scope.Name)})
	}

	t.Render()

}

func printAccessibleRepositories(repos []Repo) {
	color.Yellow("\n[i] Accessible Repositories:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Repository", "Project", "Workspace", "Owner", "Is Private", "This User's Role"})

	for _, repo := range repos {
		private := ""
		if repo.IsPrivate {
			private = color.GreenString("Yes")
		} else {
			private = color.RedString("No")
		}
		t.AppendRow([]any{
			color.GreenString(repo.RepoName),
			color.GreenString(repo.Project.Name),
			color.GreenString(repo.Workspace.Name),
			color.GreenString(repo.Owner.Username),
			private,
			color.GreenString(repo.Role),
		})
	}

	t.Render()
}
