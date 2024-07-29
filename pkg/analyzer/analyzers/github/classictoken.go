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

type githubClassicPermission struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Implies     []string `json:"implies"`
}

var GitHubClassicPerms = []githubClassicPermission{
	{
		Name:        "repo",
		Description: "Full control of private repositories",
		Implies:     []string{"repo:status", "repo_deployment", "public_repo", "repo:invite", "security_events"},
	},
	{
		Name:        "repo:status",
		Description: "Access commit status",
		Implies:     []string{},
	},
	{
		Name:        "repo_deployment",
		Description: "Access deployment status",
		Implies:     []string{},
	},
	{
		Name:        "public_repo",
		Description: "Access public repositories",
		Implies:     []string{},
	},
	{
		Name:        "repo:invite",
		Description: "Access repository invitations",
		Implies:     []string{},
	},
	{
		Name:        "security_events",
		Description: "Read and write security events",
		Implies:     []string{},
	},
	{
		Name:        "workflow",
		Description: "Update GitHub Action workflows",
		Implies:     []string{},
	},
	{
		Name:        "write:packages",
		Description: "Upload packages to GitHub Package Registry",
		Implies:     []string{"read:packages"},
	},
	{
		Name:        "read:packages",
		Description: "Download packages from GitHub Package Registry",
		Implies:     []string{},
	},
	{
		Name:        "delete:packages",
		Description: "Delete packages from GitHub Package Registry",
		Implies:     []string{},
	},
	{
		Name:        "admin:org",
		Description: "Full control of orgs and teams, read and write org projects",
		Implies:     []string{"write:org", "read:org", "manage_runners:org"},
	},
	{
		Name:        "write:org",
		Description: "Read and write org and team membership, read and write org projects",
		Implies:     []string{},
	},
	{
		Name:        "read:org",
		Description: "Read org and team membership, read org projects",
		Implies:     []string{},
	},
	{
		Name:        "manage_runners:org",
		Description: "Manage org runners and runner groups",
		Implies:     []string{},
	},
	{
		Name:        "admin:public_key",
		Description: "Full control of user public keys",
		Implies:     []string{"write:public_key", "read:public_key"},
	},
	{
		Name:        "write:public_key",
		Description: "Write user public keys",
		Implies:     []string{},
	},
	{
		Name:        "read:public_key",
		Description: "Read user public keys",
		Implies:     []string{},
	},
	{
		Name:        "admin:repo_hook",
		Description: "Full control of repository hooks",
		Implies:     []string{"write:repo_hook", "read:repo_hook"},
	},
	{
		Name:        "write:repo_hook",
		Description: "Write repository hooks",
		Implies:     []string{},
	},
	{
		Name:        "read:repo_hook",
		Description: "Read repository hooks",
		Implies:     []string{},
	},
	{
		Name:        "admin:org_hook",
		Description: "Full control of organization hooks",
		Implies:     []string{},
	},

	{
		Name:        "gist",
		Description: "Create gists",
		Implies:     []string{},
	},
	{
		Name:        "notifications",
		Description: "Access notifications",
		Implies:     []string{},
	},
	{
		Name:        "user",
		Description: "Update ALL user data",
		Implies:     []string{"read:user", "user:email", "user:follow"},
	},
	{
		Name:        "read:user",
		Description: "Read ALL user profile data",
		Implies:     []string{},
	},
	{
		Name:        "user:email",
		Description: "Access user email addresses (read-only)",
		Implies:     []string{},
	},
	{
		Name:        "user:follow",
		Description: "Follow and unfollow users",
		Implies:     []string{},
	},
	{
		Name:        "delete_repo",
		Description: "Delete repositories",
		Implies:     []string{},
	},
	{
		Name:        "write:discussion",
		Description: "Read and write team discussions",
		Implies:     []string{"read:discussion"},
	},
	{
		Name:        "read:discussion",
		Description: "Read team discussions",
		Implies:     []string{},
	},
	{
		Name:        "admin:enterprise",
		Description: "Full control of enterprises",
		Implies:     []string{"manage_runners:enterprise", "manage_billing:enterprise", "read:enterprise"},
	},
	{
		Name:        "manage_runners:enterprise",
		Description: "Manage enterprise runners and runner groups",
		Implies:     []string{},
	},
	{
		Name:        "manage_billing:enterprise",
		Description: "Read and write enterprise billing data",
		Implies:     []string{},
	},
	{
		Name:        "read:enterprise",
		Description: "Read enterprise profile data",
		Implies:     []string{},
	},
	{
		Name:        "audit_log",
		Description: "Full control of audit log",
		Implies:     []string{"read:audit_log"},
	},
	{
		Name:        "read:audit_log",
		Description: "Read access of audit log",
		Implies:     []string{},
	},
	{
		Name:        "codespace",
		Description: "Full control of codespaces",
		Implies:     []string{"codespace:secrets"},
	},
	{
		Name:        "codespace:secrets",
		Description: "Ability to create, read, update, and delete codespace secrets",
		Implies:     []string{},
	},
	{
		Name:        "copilot",
		Description: "Full control of GitHub Copilot settings and seat assignments",
		Implies:     []string{"manage_billing:copilot"},
	},
	{
		Name:        "manage_billing:copilot",
		Description: "View and edit Copilot Business seat assignments",
		Implies:     []string{},
	},
	{
		Name:        "project",
		Description: "Full control of projects",
		Implies:     []string{"read:project"},
	},
	{
		Name:        "read:project",
		Description: "Read access of projects",
		Implies:     []string{},
	},
	{
		Name:        "admin:gpg_key",
		Description: "Full control of public user GPG keys",
		Implies:     []string{"write:gpg_key", "read:gpg_key"},
	},
	{
		Name:        "write:gpg_key",
		Description: "Write public user GPG keys",
		Implies:     []string{},
	},
	{
		Name:        "read:gpg_key",
		Description: "Read public user GPG keys",
		Implies:     []string{},
	},
	{
		Name:        "admin:ssh_signing_key",
		Description: "Full control of public user SSH signing keys",
		Implies:     []string{"write:ssh_signing_key", "read:ssh_signing_key"},
	},
	{
		Name:        "write:ssh_signing_key",
		Description: "Write public user SSH signing keys",
		Implies:     []string{},
	},
	{
		Name:        "read:ssh_signing_key",
		Description: "Read public user SSH signing keys",
		Implies:     []string{},
	},
}

func hasPrivateRepoAccess(scopes map[string]bool) bool {
	return scopes["repo"]
}

func processScopes(headerScopesSlice []analyzers.Permission) map[string]bool {
	allScopes := make(map[string]bool)
	for _, scope := range headerScopesSlice {
		allScopes[scope.Value] = true
	}

	for _, perm := range GitHubClassicPerms {
		if allScopes[perm.Name] {
			for _, subScope := range perm.Implies {
				allScopes[subScope] = true
			}
		}
	}

	return allScopes
}

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

	filteredScopes := make([][]githubClassicPermission, 0)
	for _, perm := range GitHubClassicPerms {
		if scopes[perm.Name] {
			filteredScopes = append(filteredScopes, []githubClassicPermission{perm})
		}
	}

	var formattedScope, status string
	var indentation int

	if !showAll {
		for _, scopeSlice := range filteredScopes {
			for ind, perm := range scopeSlice {
				if ind == 0 {
					indentation = 0
					if scopes[perm.Name] {
						scopeCount++
						formattedScope, status = scopeFormatter(perm.Name, true, indentation)
						t.AppendRow([]any{formattedScope, status})
					} else {
						t.AppendRow([]any{perm.Name, "----"})
					}
				} else {
					indentation = 2
					if scopes[perm.Name] {
						scopeCount++
						formattedScope, status = scopeFormatter(perm.Name, true, indentation)
						t.AppendRow([]any{formattedScope, status})
					}
				}
			}
			t.AppendSeparator()
		}
	} else {
		for _, perm := range GitHubClassicPerms {
			indentation = 0
			if scopes[perm.Name] {
				scopeCount++
				formattedScope, status = scopeFormatter(perm.Name, true, indentation)
				t.AppendRow([]any{formattedScope, status})
			} else {
				formattedScope, status = scopeFormatter(perm.Name, false, indentation)
				t.AppendRow([]any{formattedScope, status})
			}
			for _, subScope := range perm.Implies {
				indentation = 2
				if scopes[subScope] {
					scopeCount++
					formattedScope, status = scopeFormatter(subScope, true, indentation)
					t.AppendRow([]any{formattedScope, status})
				} else {
					formattedScope, status = scopeFormatter(subScope, false, indentation)
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
