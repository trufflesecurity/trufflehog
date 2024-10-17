package common

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	gh "github.com/google/go-github/v66/github"
	"github.com/jedib0t/go-pretty/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
)

type TokenType string

const (
	TokenTypeFineGrainedPAT TokenType = "Fine-Grained GitHub Personal Access Token"
	TokenTypeClassicPAT     TokenType = "Classic GitHub Personal Access Token"
	TokenTypeUserToServer   TokenType = "GitHub User-to-Server Token"
	TokenTypeGitHubToken    TokenType = "GitHub Token"
)

func checkFineGrained(token string, oauthScopes []analyzers.Permission) (TokenType, bool) {
	// For details on token prefixes, see:
	// https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/

	// Special case for ghu_ prefix tokens (ex: in a codespace) that don't have the X-OAuth-Scopes header
	if strings.HasPrefix(token, "ghu_") {
		return TokenTypeUserToServer, true
	}

	// Handle github_pat_ tokens
	if strings.HasPrefix(token, "github_pat") {
		return TokenTypeFineGrainedPAT, true
	}

	// Handle classic PATs
	if strings.HasPrefix(token, "ghp_") {
		return TokenTypeClassicPAT, false
	}

	// Catch-all for any other types
	// If resp.Header "X-OAuth-Scopes" doesn't exist, then we have fine-grained permissions
	if len(oauthScopes) > 0 {
		return TokenTypeGitHubToken, false
	}
	return TokenTypeGitHubToken, true
}

type Permission int

type SecretInfo struct {
	Metadata *TokenMetadata
	Repos    []*gh.Repository
	Gists    []*gh.Gist
	// AccessibleRepos, RepoAccessMap, and UserAccessMap are only set if
	// the token has fine-grained access.
	AccessibleRepos []*gh.Repository
	RepoAccessMap   any
	UserAccessMap   any
}

type TokenMetadata struct {
	Type        TokenType
	FineGrained bool
	User        *gh.User
	Expiration  time.Time
	// OauthScopes is only set for classic tokens.
	OauthScopes []analyzers.Permission
}

// GetTokenMetadata gets the username, expiration date, and x-oauth-scopes headers for a given token
// by sending a GET request to the /user endpoint
// Returns a response object for usage in the checkFineGrained function
func GetTokenMetadata(token string, client *gh.Client) (*TokenMetadata, error) {
	user, resp, err := client.Users.Get(context.Background(), "")
	if err != nil {
		return nil, err
	}

	expiration, _ := time.Parse("2006-01-02 15:04:05 -0700", resp.Header.Get("github-authentication-token-expiration"))

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

func GetAllGistsForUser(client *gh.Client) ([]*gh.Gist, error) {
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

func GetAllReposForUser(client *gh.Client) ([]*gh.Repository, error) {
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

func PrintGitHubRepos(repos []*gh.Repository) {
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

func PrintGists(gists []*gh.Gist, showAll bool) {
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
