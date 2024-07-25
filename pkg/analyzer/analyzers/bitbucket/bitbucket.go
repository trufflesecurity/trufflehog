package bitbucket

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

type Repo struct {
	FullName string `json:"full_name"`
	RepoName string `json:"name"`
	Project  struct {
		Name string `json:"name"`
	} `json:"project"`
	Workspace struct {
		Name string `json:"name"`
	} `json:"workspace"`
	IsPrivate bool `json:"is_private"`
	Owner     struct {
		Username string `json:"username"`
	} `json:"owner"`
	Role string
}

type RepoJSON struct {
	Values []Repo `json:"values"`
}

func getScopesAndType(cfg *config.Config, key string) (string, string, error) {

	// client
	client := analyzers.NewAnalyzeClient(cfg)

	// request
	req, err := http.NewRequest("GET", "https://api.bitbucket.org/2.0/repositories", nil)
	if err != nil {
		return "", "", err
	}

	// headers
	req.Header.Set("Authorization", "Bearer "+key)

	// response
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	// parse response headers
	credentialType := resp.Header.Get("x-credential-type")
	oauthScopes := resp.Header.Get("x-oauth-scopes")

	return credentialType, oauthScopes, nil
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

func getAllRepos(cfg *config.Config, key string) (map[string]Repo, error) {
	roles := []string{"member", "contributor", "admin", "owner"}

	var allRepos = make(map[string]Repo, 0)
	for _, role := range roles {
		repos, err := getRepositories(cfg, key, role)
		if err != nil {
			return allRepos, err
		}
		// purposefully overwriting, so that get the most permissive role
		for _, repo := range repos.Values {
			repo.Role = role
			allRepos[repo.FullName] = repo
		}
	}
	return allRepos, nil
}

func AnalyzePermissions(cfg *config.Config, key string) {

	credentialType, oauthScopes, err := getScopesAndType(cfg, key)
	if err != nil {
		color.Red("Error: %s", err)
		return
	}
	printScopes(credentialType, oauthScopes)

	// get all repos available to user
	// ToDo: pagination
	repos, err := getAllRepos(cfg, key)
	if err != nil {
		color.Red("Error: %s", err)
		return
	}

	printAccessibleRepositories(repos)

}

func printScopes(credentialType string, oauthScopes string) {
	if credentialType == "" {
		color.Red("[x] Invalid Bitbucket access token.")
		return
	}
	color.Green("[!] Valid Bitbucket access token.\n\n")
	color.Green("[i] Credential Type: %s\n\n", credential_type_map[credentialType])

	scopes := strings.Split(oauthScopes, ", ")
	scopesSlice := []BitbucketScope{}
	for _, scope := range scopes {
		mapping := oauth_scope_map[scope]
		for _, impliedScope := range mapping.ImpliedScopes {
			scopesSlice = append(scopesSlice, oauth_scope_map[impliedScope])
		}
		scopesSlice = append(scopesSlice, oauth_scope_map[scope])
	}

	// sort scopes by category
	sort.Sort(ByCategoryAndName(scopesSlice))

	color.Yellow("[i] Access Token Scopes:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Category", "Permission"})

	currentCategory := ""
	for _, scope := range scopesSlice {
		if currentCategory != scope.Category {
			currentCategory = scope.Category
			t.AppendRow([]interface{}{scope.Category, ""})
		}
		t.AppendRow([]interface{}{"", color.GreenString(scope.Name)})
	}

	t.Render()

}

func printAccessibleRepositories(repos map[string]Repo) {
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
		t.AppendRow([]interface{}{color.GreenString(repo.RepoName), color.GreenString(repo.Project.Name), color.GreenString(repo.Workspace.Name), color.GreenString(repo.Owner.Username), private, color.GreenString(repo.Role)})
	}

	t.Render()
}
