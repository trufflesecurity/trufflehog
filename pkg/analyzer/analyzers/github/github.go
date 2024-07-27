package github

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	gh "github.com/google/go-github/v63/github"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/pb/analyzerpb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzerpb.AnalyzerType { return analyzerpb.AnalyzerType_GitHub }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	info, err := AnalyzePermissions(a.Cfg, credInfo["key"])
	if err != nil {
		return nil, err
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}
	// Metadata        *TokenMetadata
	//	Type        string
	//	FineGrained bool
	//	User        *gh.User
	//	Expiration  time.Time
	//	OauthScopes []analyzers.Permission
	// Repos           []*gh.Repository
	// Gists           []*gh.Gist
	// AccessibleRepos []*gh.Repository
	// RepoAccessMap   map[string]string
	// UserAccessMap   map[string]string
	result := &analyzers.AnalyzerResult{
		Metadata: map[string]any{
			"type":         info.Metadata.Type,
			"fine_grained": info.Metadata.FineGrained,
			"expiration":   info.Metadata.Expiration,
		},
	}
	result.Bindings = append(result.Bindings, secretInfoToUserBindings(info)...)
	result.Bindings = append(result.Bindings, secretInfoToRepoBindings(info)...)
	result.Bindings = append(result.Bindings, secretInfoToGistBindings(info)...)
	for _, repo := range append(info.Repos, info.AccessibleRepos...) {
		if *repo.Owner.Type != "Organization" {
			continue
		}
		name := *repo.Owner.Name
		result.UnboundedResources = append(result.UnboundedResources, analyzers.Resource{
			Name:               name,
			FullyQualifiedName: fmt.Sprintf("github.com/%s", name),
			Type:               "organization",
		})
	}
	// TODO: Unbound resources
	// - Repo owners
	// - Gist owners
	return result
}

func secretInfoToUserBindings(info *SecretInfo) []analyzers.Binding {
	return analyzers.BindAllPermissions(*userToResource(info.Metadata.User), info.Metadata.OauthScopes...)
}

func userToResource(user *gh.User) *analyzers.Resource {
	name := *user.Login
	return &analyzers.Resource{
		Name:               name,
		FullyQualifiedName: fmt.Sprintf("github.com/%s", name),
		Type:               strings.ToLower(*user.Type), // "user" or "organization"
	}
}

func secretInfoToRepoBindings(info *SecretInfo) []analyzers.Binding {
	repos := info.Repos
	if len(info.AccessibleRepos) > 0 {
		repos = info.AccessibleRepos
	}
	var bindings []analyzers.Binding
	for _, repo := range repos {
		resource := analyzers.Resource{
			Name:               *repo.Name,
			FullyQualifiedName: fmt.Sprintf("github.com/%s", *repo.FullName),
			Type:               "repository",
			Parent:             userToResource(repo.Owner),
		}
		bindings = append(bindings, analyzers.BindAllPermissions(resource, info.Metadata.OauthScopes...)...)
	}
	return bindings
}

func secretInfoToGistBindings(info *SecretInfo) []analyzers.Binding {
	var bindings []analyzers.Binding
	for _, gist := range info.Gists {
		resource := analyzers.Resource{
			Name:               *gist.Description,
			FullyQualifiedName: fmt.Sprintf("gist.github.com/%s/%s", *gist.Owner.Login, *gist.ID),
			Type:               "gist",
			Parent:             userToResource(gist.Owner),
		}
		bindings = append(bindings, analyzers.BindAllPermissions(resource, info.Metadata.OauthScopes...)...)
	}
	return bindings
}

func getAllGistsForUser(client *gh.Client) ([]*gh.Gist, error) {
	opt := &gh.GistListOptions{ListOptions: gh.ListOptions{PerPage: 100}}
	var allGists []*gh.Gist
	page := 1
	for {
		opt.Page = page
		gists, resp, err := client.Gists.List(context.Background(), "", opt)
		if err != nil {
			color.Red("Error getting gists.")
			return nil, err
		}
		allGists = append(allGists, gists...)

		linkHeader := resp.Header.Get("link")
		if linkHeader == "" || !strings.Contains(linkHeader, `rel="next"`) {
			break
		}
		page++

	}

	return allGists, nil
}

func getAllReposForUser(client *gh.Client) ([]*gh.Repository, error) {
	opt := &gh.RepositoryListByAuthenticatedUserOptions{ListOptions: gh.ListOptions{PerPage: 100}}
	var allRepos []*gh.Repository
	page := 1
	for {
		opt.Page = page
		repos, resp, err := client.Repositories.ListByAuthenticatedUser(context.Background(), opt)
		if err != nil {
			color.Red("Error getting repos.")
			return nil, err
		}
		allRepos = append(allRepos, repos...)

		linkHeader := resp.Header.Get("link")
		if linkHeader == "" || !strings.Contains(linkHeader, `rel="next"`) {
			break
		}
		page++

	}
	return allRepos, nil
}

func printGitHubRepos(repos []*gh.Repository) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Repo Name", "Owner", "Repo Link", "Private"})
	for _, repo := range repos {
		if *repo.Private {
			green := color.New(color.FgGreen).SprintFunc()
			t.AppendRow([]interface{}{green(*repo.Name), green(*repo.Owner.Login), green(*repo.HTMLURL), green("true")})
		} else {
			t.AppendRow([]interface{}{*repo.Name, *repo.Owner.Login, *repo.HTMLURL, *repo.Private})
		}
	}
	t.Render()
	fmt.Print("\n\n")
}

func printGists(gists []*gh.Gist, showAll bool) {
	privateCount := 0

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Gist ID", "Gist Link", "Description", "Private"})
	for _, gist := range gists {
		if showAll && *gist.Public {
			t.AppendRow([]interface{}{*gist.ID, *gist.HTMLURL, *gist.Description, "false"})
		} else if !*gist.Public {
			privateCount++
			green := color.New(color.FgGreen).SprintFunc()
			t.AppendRow([]interface{}{green(*gist.ID), green(*gist.HTMLURL), green(*gist.Description), green("true")})
		}
	}
	if showAll && len(gists) == 0 {
		color.Red("[i] No Gist(s) Found\n")
	} else if showAll {
		color.Yellow("[i] Found %v Total Gist(s) (%v private)\n", len(gists), privateCount)
		t.Render()
	} else if privateCount == 0 {
		color.Red("[i] No Private Gist(s) Found\n")
	} else {
		color.Green(fmt.Sprintf("[!] Found %v Private Gist(s)\n", privateCount))
		t.Render()
	}
	fmt.Print("\n\n")
}

type TokenMetadata struct {
	Type        string
	FineGrained bool
	User        *gh.User
	Expiration  time.Time
	OauthScopes []analyzers.Permission
}

// getTokenMetadata gets the username, expiration date, and x-oauth-scopes headers for a given token
// by sending a GET request to the /user endpoint
// Returns a response object for usage in the checkFineGrained function
func getTokenMetadata(token string, client *gh.Client) (*TokenMetadata, error) {
	user, resp, err := client.Users.Get(context.Background(), "")
	if err != nil {
		return nil, err
	}

	expiration, _ := time.Parse("2006-01-02 15:04:05 MST", resp.Header.Get("github-authentication-token-expiration"))

	var oauthScopes []analyzers.Permission
	for _, scope := range resp.Header.Values("X-OAuth-Scopes") {
		for _, scope := range strings.Split(scope, ", ") {
			oauthScopes = append(oauthScopes, analyzers.Permission{Value: scope})
		}
	}
	tokenType, fineGrained := checkFineGrained(token, oauthScopes)
	return &TokenMetadata{
		Type:        tokenType,
		FineGrained: fineGrained,
		User:        user,
		Expiration:  expiration,
		OauthScopes: oauthScopes,
	}, nil
}

func checkFineGrained(token string, oauthScopes []analyzers.Permission) (string, bool) {
	// For details on token prefixes, see:
	// https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/

	// Special case for ghu_ prefix tokens (ex: in a codespace) that don't have the X-OAuth-Scopes header
	if strings.HasPrefix(token, "ghu_") {
		return "GitHub User-to-Server Token", true
	}

	// Handle github_pat_ tokens
	if strings.HasPrefix(token, "github_pat") {
		return "Fine-Grained GitHub Personal Access Token", true
	}

	// Handle classic PATs
	if strings.HasPrefix(token, "ghp_") {
		return "Classic GitHub Personal Access Token", false
	}

	// Catch-all for any other types
	// If resp.Header "X-OAuth-Scopes" doesn't exist, then we have fine-grained permissions
	if len(oauthScopes) > 0 {
		return "GitHub Token", false
	}
	return "GitHub Token", true
}

type SecretInfo struct {
	Metadata *TokenMetadata
	Repos    []*gh.Repository
	Gists    []*gh.Gist
	// AccessibleRepos, RepoAccessMap, and UserAccessMap are only set if
	// the token has fine-grained access.
	AccessibleRepos []*gh.Repository
	RepoAccessMap   map[string]string
	UserAccessMap   map[string]string
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	client := gh.NewClient(analyzers.NewAnalyzeClient(cfg)).WithAuthToken(key)

	md, err := getTokenMetadata(key, client)
	if err != nil {
		return nil, err
	}

	if md.FineGrained {
		return analyzeFineGrainedToken(client, md, cfg.Shallow)
	}
	return analyzeClassicToken(client, md)
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] %s", err.Error())
		return
	}

	color.Yellow("[i] Token User: %v", *info.Metadata.User.Login)
	if expiry := info.Metadata.Expiration; expiry.IsZero() {
		color.Red("[i] Token Expiration: does not expire")
	} else {
		timeRemaining := time.Until(expiry)
		color.Yellow("[i] Token Expiration: %v (%v remaining)", expiry, timeRemaining)
	}
	color.Yellow("[i] Token Type: %s\n\n", info.Metadata.Type)

	if info.Metadata.FineGrained {
		printFineGrainedToken(cfg, info)
		return
	}
	printClassicToken(cfg, info)
}
