package github

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	gh "github.com/google/go-github/v59/github"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/pb/analyzerpb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/pb/resourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzerpb.SecretType { return analyzerpb.SecretType_GITHUB }

func (a Analyzer) Analyze(_ context.Context, key string, _ map[string]string) (*analyzers.AnalyzerResult, error) {
	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, err
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	// TODO: Tree-ify repos
	if info == nil {
		return nil
	}

	// Copy metadata into SecretMetadata (Type, Expiration)
	result := analyzers.AnalyzerResult{
		SecretMetadata: map[string]string{
			"type":       info.Metadata.Type,
			"expiration": info.Metadata.Expiration.String(),
		},
	}

	// Metadata        *TokenMetadata
	//	Type        string
	// 	FineGrained bool
	// 	User        *gh.User
	// 	Expiration  time.Time
	// 	OauthScopes []analyzers.Permission
	// Repos           []*gh.Repository
	// Gists           []*gh.Gist
	// AccessibleRepos []*gh.Repository
	// RepoAccessMap   map[string]string
	// UserAccessMap   map[string]string

	// Create the list of permissions from Metadata.OauthScopes,
	// RepoAccessMap, and UserAccessMap. For now, assume that all
	// permissions apply to all resources of all types.
	// TODO: Re-assess whether this makes sense.
	permissions := make([]analyzers.Permission, 0, len(info.Metadata.OauthScopes)+len(info.RepoAccessMap)+len(info.UserAccessMap))

	// Copy existing oauth scopes.
	copy(permissions, info.Metadata.OauthScopes)

	// Copy permissions enumerated from RepoAccessMap.
	for scope, access := range info.RepoAccessMap {
		if !significantPermissions(access) {
			continue
		}
		permissions = append(permissions, analyzers.Permission(scope))
	}

	// Copy permissions enumerated from UserAccessMap.
	for scope, access := range info.UserAccessMap {
		if !significantPermissions(access) {
			continue
		}
		permissions = append(permissions, analyzers.Permission(scope))
	}

	// Add repos to the list of resources (if AccessibleRepos is available,
	// use that instead).
	repos := info.Repos
	if len(info.AccessibleRepos) > 0 {
		repos = info.AccessibleRepos
	}
	for _, repo := range repos {
		rp := analyzers.ResourcePermission{
			ResourceTree: analyzers.ResourceTree{
				Resource: &resourcespb.Resource{
					SecretType:   analyzerpb.SecretType_GITHUB,
					ResourceType: resourcespb.ResourceType_REPOSITORY,
					Name:         *repo.Name,
					Metadata: map[string]string{
						"full_name": repo.GetFullName(),
						"private":   strconv.FormatBool(repo.GetPrivate()),
					},
				},
			},
			Permissions: permissions,
		}

		result.ResourcePermissions = append(result.ResourcePermissions, rp)
	}

	// Add gists to the list of resources.
	for _, gist := range info.Gists {
		rp := analyzers.ResourcePermission{
			ResourceTree: analyzers.ResourceTree{
				Resource: &resourcespb.Resource{
					SecretType:   analyzerpb.SecretType_GITHUB,
					ResourceType: resourcespb.ResourceType_GIST,
					Name:         gist.GetID(),
					Metadata:     map[string]string{},
				},
			},
			Permissions: permissions,
		}

		result.ResourcePermissions = append(result.ResourcePermissions, rp)
	}

	// Add user to the list of resources.
	result.ResourcePermissions = append(result.ResourcePermissions, analyzers.ResourcePermission{
		ResourceTree: analyzers.ResourceTree{
			Resource: &resourcespb.Resource{
				SecretType:   analyzerpb.SecretType_GITHUB,
				ResourceType: resourcespb.ResourceType_USER,
				Name:         *info.Metadata.User.Login,
				Metadata:     map[string]string{},
			},
		},
	})

	return &result
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

func getRemainingTime(t string) string {
	targetTime, err := time.Parse("2006-01-02 15:04:05 MST", t)
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
			oauthScopes = append(oauthScopes, analyzers.Permission(scope))
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
	Metadata        *TokenMetadata
	Repos           []*gh.Repository
	Gists           []*gh.Gist
	AccessibleRepos []*gh.Repository
	RepoAccessMap   map[string]string
	UserAccessMap   map[string]string
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	client := gh.NewClient(analyzers.NewAnalyzeClient(cfg)).WithAuthToken(key)

	md, err := getTokenMetadata(key, client)
	if err != nil {
		return nil, err
	}

	if md.FineGrained {
		return analyzeFineGrainedToken(client, md)
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
