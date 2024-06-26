package github

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	gh "github.com/google/go-github/v59/github"
	"github.com/jedib0t/go-pretty/v6/table"
)

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

func printGists(gists []*gh.Gist, show_all bool) {
	privateCount := 0

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Gist ID", "Gist Link", "Description", "Private"})
	for _, gist := range gists {
		if show_all && *gist.Public {
			t.AppendRow([]interface{}{*gist.ID, *gist.HTMLURL, *gist.Description, "false"})
		} else if !*gist.Public {
			privateCount++
			green := color.New(color.FgGreen).SprintFunc()
			t.AppendRow([]interface{}{green(*gist.ID), green(*gist.HTMLURL), green(*gist.Description), green("true")})
		}
	}
	if show_all && len(gists) == 0 {
		color.Red("[i] No Gist(s) Found\n")
	} else if show_all {
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

// getTokenMetadata gets the username, expiration date, and x-oauth-scopes headers for a given token
// by sending a GET request to the /user endpoint
// Returns a response object for usage in the checkFineGrained function
func getTokenMetadata(token string, client *gh.Client) (resp *gh.Response, err error) {
	user, resp, err := client.Users.Get(context.Background(), "")
	if err != nil {
		return nil, err
	}

	color.Yellow("[i] Token User: %v", *user.Login)

	expiry := resp.Header.Get("github-authentication-token-expiration")
	timeRemaining := getRemainingTime(expiry)
	if timeRemaining == "" {
		color.Red("[i] Token Expiration: does not expire")
	} else {
		color.Yellow("[i] Token Expiration: %v (%v remaining)", expiry, timeRemaining)
	}
	return resp, nil
}

func checkFineGrained(resp *gh.Response, token string) (bool, error) {
	// For details on token prefixes, see:
	// https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/

	// Special case for ghu_ prefix tokens (ex: in a codespace) that don't have the X-OAuth-Scopes header
	if strings.HasPrefix(token, "ghu_") {
		color.Yellow("[i] Token Type: GitHub User-to-Server Token")
		return true, nil
	}

	// Handle github_pat_ tokens
	if strings.HasPrefix(token, "github_pat") {
		color.Yellow("[i] Token Type: Fine-Grained GitHub Personal Access Token")
		return true, nil
	}

	// Handle classic PATs
	if strings.HasPrefix(token, "ghp_") {
		color.Yellow("[i] Token Type: Classic GitHub Personal Access Token")
		return false, nil
	}

	// Catch-all for any other types
	// If resp.Header "X-OAuth-Scopes" doesn't exist, then we have fine-grained permissions
	color.Yellow("[i] Token Type: GitHub Token")
	if len(resp.Header.Values("X-Oauth-Scopes")) > 0 {
		return false, nil
	}
	return true, nil
}

func AnalyzePermissions(key string, show_all bool) {
	client := gh.NewClient(nil).WithAuthToken(key)

	resp, err := getTokenMetadata(key, client)
	if err != nil {
		color.Red("[x] Invalid GitHub Token.")
		return
	}

	// Check if the token is fine-grained or classic
	if fineGrained, err := checkFineGrained(resp, key); err != nil {
		color.Red("[x] Invalid GitHub Token.")
		return
	} else if !fineGrained {
		fmt.Print("\n\n")
		analyzeClassicToken(client, key, show_all)
	} else {
		fmt.Print("\n\n")
		analyzeFineGrainedToken(client, key, show_all)
	}
}
