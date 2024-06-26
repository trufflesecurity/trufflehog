package github

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/fatih/color"
	gh "github.com/google/go-github/v59/github"
	"github.com/jedib0t/go-pretty/v6/table"
)

// var SCOPE_ORDER = []string{"repo", "repo:status", "repo_deployment", "public_repo", "repo:invite", "security_events", "--", "workflow", "--", "write:packages", "read:packages", "--", "delete:packages", "--", "admin:org", "write:org", "read:org", "manage_runners:org", "--", "admin:public_key", "write:public_key", "read:public_key", "--", "admin:repo_hook", "write:repo_hook", "read:repo_hook", "--", "admin:org_hook", "--", "gist", "--", "notifications", "--", "user", "read:user", "user:email", "user:follow", "--", "delete_repo", "--", "write:discussion", "read:discussion", "--", "admin:enterprise", "manage_runners:enterprise", "manage_billing:enterprise", "read:enterprise", "--", "audit_log", "read:audit_log", "--", "codespace", "codespace:secrets", "--", "copilot", "manage_billing:copilot", "--", "project", "read:project", "--", "admin:gpg_key", "write:gpg_key", "read:gpg_key", "--", "admin:ssh_signing_key", "write:ssh_signing_key", "read:ssh_signing_key"}

var SCOPE_ORDER = [][]string{{"repo", "repo:status", "repo_deployment", "public_repo", "repo:invite", "security_events"}, {"workflow"}, {"write:packages", "read:packages"}, {"delete:packages"}, {"admin:org", "write:org", "read:org", "manage_runners:org"}, {"admin:public_key", "write:public_key", "read:public_key"}, {"admin:repo_hook", "write:repo_hook", "read:repo_hook"}, {"admin:org_hook"}, {"gist"}, {"notifications"}, {"user", "read:user", "user:email", "user:follow"}, {"delete_repo"}, {"write:discussion", "read:discussion"}, {"admin:enterprise", "manage_runners:enterprise", "manage_billing:enterprise", "read:enterprise"}, {"audit_log", "read:audit_log"}, {"codespace", "codespace:secrets"}, {"copilot", "manage_billing:copilot"}, {"project", "read:project"}, {"admin:gpg_key", "write:gpg_key", "read:gpg_key"}, {"admin:ssh_signing_key", "write:ssh_signing_key", "read:ssh_signing_key"}}

var SCOPE_TO_SUB_SCOPE = map[string][]string{
	"repo":                      {"repo:status", "repo_deployment", "public_repo", "repo:invite", "security_events"},
	"write:pakages":             {"read:packages"},
	"admin:org":                 {"write:org", "read:org", "manage_runners:org"},
	"write:org":                 {"read:org"},
	"admin:public_key":          {"write:public_key", "read:public_key"},
	"write:public_key":          {"read:public_key"},
	"admin:repo_hook":           {"write:repo_hook", "read:repo_hook"},
	"write:repo_hook":           {"read:repo_hook"},
	"user":                      {"read:user", "user:email", "user:follow"},
	"write:discussion":          {"read:discussion"},
	"admin:enterprise":          {"manage_runners:enterprise", "manage_billing:enterprise", "read:enterprise"},
	"manage_billing:enterprise": {"read:enterprise"},
	"audit_log":                 {"read:audit_log"},
	"codespace":                 {"codespace:secrets"},
	"copilot":                   {"manage_billing:copilot"},
	"project":                   {"read:project"},
	"admin:gpg_key":             {"write:gpg_key", "read:gpg_key"},
	"write:gpg_key":             {"read:gpg_key"},
	"admin:ssh_signing_key":     {"write:ssh_signing_key", "read:ssh_signing_key"},
	"write:ssh_signing_key":     {"read:ssh_signing_key"},
}

func checkPrivateRepoAccess(scopes map[string]bool) []string {
	var currPrivateScopes []string
	privateScopes := []string{"repo", "repo:status", "repo_deployment", "repo:invite", "security_events", "admin:repo_hook", "write:repo_hook", "read:repo_hook"}
	for _, scope := range privateScopes {
		if scopes[scope] {
			currPrivateScopes = append(currPrivateScopes, scope)
		}
	}
	return currPrivateScopes
}

func processScopes(headerScopesSlice []string) map[string]bool {
	allScopes := make(map[string]bool)
	for _, scope := range headerScopesSlice {
		allScopes[scope] = true
	}
	for scope := range allScopes {
		if subScopes, ok := SCOPE_TO_SUB_SCOPE[scope]; ok {
			for _, subScope := range subScopes {
				allScopes[subScope] = true
			}
		}
	}
	return allScopes
}

// The `gists` scope is required to update private gists. Anyone can access a private gist with the link.
//  These tokens can seem to list out the private repos, but access will depend on scopes.

func analyzeClassicToken(client *gh.Client, token string, show_all bool) {

	// Issue GET request to /user
	user, resp, err := client.Users.Get(context.Background(), "")
	if err != nil {
		color.Red("[x] Invalid GitHub Token.")
		return
	}

	// If resp.Header "X-OAuth-Scopes", parse the scopes into a map[string]bool
	headerScopes := resp.Header.Get("X-OAuth-Scopes")

	var scopes = make(map[string]bool)
	if headerScopes == "" {
		color.Red("[x] Classic Token has no scopes.")
	} else {
		// Split string into slice of strings
		headerScopesSlice := strings.Split(headerScopes, ", ")
		scopes = processScopes(headerScopesSlice)
	}

	printClassicGHPermissions(scopes, show_all)

	// Check if private repo access
	privateScopes := checkPrivateRepoAccess(scopes)

	if len(privateScopes) > 0 && slices.Contains(privateScopes, "repo") {
		color.Green("[!] Token has scope(s) for both public and private repositories. Here's a list of all accessible repositories:")
		repos, _ := getAllReposForUser(client)
		printGitHubRepos(repos)
	} else if len(privateScopes) > 0 {
		color.Yellow("[!] Token has scope(s) useful for accessing both public and private repositories.\n    However, without the `repo` scope, we cannot enumerate or access code from private repos.\n    Review the permissions associated with the following scopes for more details: %v", strings.Join(privateScopes, ", "))
	} else if scopes["public_repo"] {
		color.Yellow("[i] Token is scoped to only public repositories. See https://github.com/%v?tab=repositories", *user.Login)
	} else {
		color.Red("[x] Token does not appear scoped to any specific repositories.")
	}

	// Get all private gists
	gists, err := getAllGistsForUser(client)
	printGists(gists, show_all)

}

// Question: can you access private repo with those other permissions? or can we just not list them?

func scopeFormatter(scope string, checked bool, indentation int) (string, string) {
	if indentation != 0 {
		scope = strings.Repeat("  ", indentation) + scope
	}
	if checked {
		return color.GreenString(scope), color.GreenString("true")
	} else {
		return scope, "false"
	}
}

func printClassicGHPermissions(scopes map[string]bool, show_all bool) {
	scopeCount := 0
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Scope", "In-Scope" /* Add more column headers if needed */})

	filteredScopes := make([][]string, 0)
	for _, scopeSlice := range SCOPE_ORDER {
		for _, scope := range scopeSlice {
			if scopes[scope] {
				filteredScopes = append(filteredScopes, scopeSlice)
				break
			}
		}
	}

	// For ease of reading, divide the scopes into sections, just like the GH UI
	var formattedScope, status string
	var indentation int

	if !show_all {
		for _, scopeSlice := range filteredScopes {
			for ind, scope := range scopeSlice {
				if ind == 0 {
					indentation = 0
					if scopes[scope] {
						scopeCount++
						formattedScope, status = scopeFormatter(scope, true, indentation)
						t.AppendRow([]interface{}{formattedScope, status})
					} else {
						t.AppendRow([]interface{}{scope, "----"})
					}
				} else {
					indentation = 2
					if scopes[scope] {
						scopeCount++
						formattedScope, status = scopeFormatter(scope, true, indentation)
						t.AppendRow([]interface{}{formattedScope, status})
					}
				}
			}
			t.AppendSeparator()
		}
	} else {
		for _, scopeSlice := range SCOPE_ORDER {
			for ind, scope := range scopeSlice {
				if ind == 0 {
					indentation = 0
				} else {
					indentation = 2
				}
				if scopes[scope] {
					scopeCount++
					formattedScope, status = scopeFormatter(scope, true, indentation)
					t.AppendRow([]interface{}{formattedScope, status})
				} else {
					formattedScope, status = scopeFormatter(scope, false, indentation)
					t.AppendRow([]interface{}{formattedScope, status})
				}
			}
			t.AppendSeparator()
		}
	}

	if scopeCount == 0 && !show_all {
		color.Red("No Scopes Found for the GitHub Token above\n\n")
		return
	} else if scopeCount == 0 {
		color.Red("Found No Scopes for the GitHub Token above\n")
	} else {
		color.Green(fmt.Sprintf("[!] Found %v Scope(s) for the GitHub Token above\n", scopeCount))
	}
	t.Render()
	fmt.Println("\n")
}
