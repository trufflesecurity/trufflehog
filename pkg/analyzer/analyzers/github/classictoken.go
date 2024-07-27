package github

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	gh "github.com/google/go-github/v63/github"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

var SCOPE_ORDER = [][]string{
	{"repo", "repo:status", "repo_deployment", "public_repo", "repo:invite", "security_events"},
	{"workflow"},
	{"write:packages", "read:packages"},
	{"delete:packages"},
	{"admin:org", "write:org", "read:org", "manage_runners:org"},
	{"admin:public_key", "write:public_key", "read:public_key"},
	{"admin:repo_hook", "write:repo_hook", "read:repo_hook"},
	{"admin:org_hook"},
	{"gist"},
	{"notifications"},
	{"user", "read:user", "user:email", "user:follow"},
	{"delete_repo"},
	{"write:discussion", "read:discussion"},
	{"admin:enterprise", "manage_runners:enterprise", "manage_billing:enterprise", "read:enterprise"},
	{"audit_log", "read:audit_log"},
	{"codespace", "codespace:secrets"},
	{"copilot", "manage_billing:copilot"},
	{"project", "read:project"},
	{"admin:gpg_key", "write:gpg_key", "read:gpg_key"},
	{"admin:ssh_signing_key", "write:ssh_signing_key", "read:ssh_signing_key"},
}

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

func hasPrivateRepoAccess(scopes map[string]bool) bool {
	// privateScopes := []string{"repo", "repo:status", "repo_deployment", "repo:invite", "security_events", "admin:repo_hook", "write:repo_hook", "read:repo_hook"}
	return scopes["repo"]
}

func processScopes(headerScopesSlice []analyzers.Permission) map[string]bool {
	allScopes := make(map[string]bool)
	for _, scope := range headerScopesSlice {
		allScopes[scope.Value] = true
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
// These tokens can seem to list out the private repos, but access will depend on scopes.
func analyzeClassicToken(client *gh.Client, meta *TokenMetadata) (*SecretInfo, error) {
	scopes := processScopes(meta.OauthScopes)

	var repos []*gh.Repository
	if hasPrivateRepoAccess(scopes) {
		var err error
		repos, err = getAllReposForUser(client)
		if err != nil {
			return nil, err
		}
	}

	// Get all private gists
	gists, err := getAllGistsForUser(client)
	if err != nil {
		return nil, err
	}

	return &SecretInfo{
		Metadata: meta,
		Repos:    repos,
		Gists:    gists,
	}, nil
}

func filterPrivateRepoScopes(scopes map[string]bool) []string {
	var intersection []string
	privateScopes := []string{"repo", "repo:status", "repo_deployment", "repo:invite", "security_events", "admin:repo_hook", "write:repo_hook", "read:repo_hook"}

	for _, privScope := range privateScopes {
		if scopes[privScope] {
			intersection = append(intersection, privScope)
		}
	}
	return intersection
}

func printClassicToken(cfg *config.Config, info *SecretInfo) {
	scopes := processScopes(info.Metadata.OauthScopes)
	if len(scopes) == 0 {
		color.Red("[x] Classic Token has no scopes")
	} else {
		printClassicGHPermissions(scopes, cfg.ShowAll)
	}

	// Check if private repo access
	privateScopes := filterPrivateRepoScopes(scopes)
	if hasPrivateRepoAccess(scopes) {
		color.Green("[!] Token has scope(s) for both public and private repositories. Here's a list of all accessible repositories:")
		printGitHubRepos(info.Repos)
	} else if len(privateScopes) > 0 {
		color.Yellow("[!] Token has scope(s) useful for accessing both public and private repositories.\n    However, without the `repo` scope, we cannot enumerate or access code from private repos.\n    Review the permissions associated with the following scopes for more details: %v", strings.Join(privateScopes, ", "))
	} else if scopes["public_repo"] {
		color.Yellow("[i] Token is scoped to only public repositories. See https://github.com/%v?tab=repositories", *info.Metadata.User.Login)
	} else {
		color.Red("[x] Token does not appear scoped to any specific repositories.")
	}
	printGists(info.Gists, cfg.ShowAll)
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

func printClassicGHPermissions(scopes map[string]bool, showAll bool) {
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

	if !showAll {
		for _, scopeSlice := range filteredScopes {
			for ind, scope := range scopeSlice {
				if ind == 0 {
					indentation = 0
					if scopes[scope] {
						scopeCount++
						formattedScope, status = scopeFormatter(scope, true, indentation)
						t.AppendRow([]any{formattedScope, status})
					} else {
						t.AppendRow([]any{scope, "----"})
					}
				} else {
					indentation = 2
					if scopes[scope] {
						scopeCount++
						formattedScope, status = scopeFormatter(scope, true, indentation)
						t.AppendRow([]any{formattedScope, status})
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
					t.AppendRow([]any{formattedScope, status})
				} else {
					formattedScope, status = scopeFormatter(scope, false, indentation)
					t.AppendRow([]any{formattedScope, status})
				}
			}
			t.AppendSeparator()
		}
	}

	if scopeCount == 0 && !showAll {
		color.Red("No Scopes Found for the GitHub Token above\n\n")
		return
	} else if scopeCount == 0 {
		color.Red("Found No Scopes for the GitHub Token above\n")
	} else {
		color.Green(fmt.Sprintf("[!] Found %v Scope(s) for the GitHub Token above\n", scopeCount))
	}
	t.Render()
	fmt.Print("\n\n")
}
