//go:generate generate_permissions classic.yaml classic_permissions.go classic

package classic

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	gh "github.com/google/go-github/v63/github"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

var SCOPE_ORDER = [][]Permission{
	{Repo, RepoStatus, RepoDeployment, PublicRepo, RepoInvite, SecurityEvents},
	{Workflow},
	{WritePackages, ReadPackages},
	{DeletePackages},
	{AdminOrg, WriteOrg, ReadOrg, ManageRunnersOrg},
	{AdminPublicKey, WritePublicKey, ReadPublicKey},
	{AdminRepoHook, WriteRepoHook, ReadRepoHook},
	{AdminOrgHook},
	{Gist},
	{Notifications},
	{User, ReadUser, UserEmail, UserFollow},
	{DeleteRepo},
	{WriteDiscussion, ReadDiscussion},
	{AdminEnterprise, ManageRunnersEnterprise, ManageBillingEnterprise, ReadEnterprise},
	{AuditLog, ReadAuditLog},
	{Codespace, CodespaceSecrets},
	{Copilot, ManageBillingCopilot},
	{Project, ReadProject},
	{AdminGpgKey, WriteGpgKey, ReadGpgKey},
	{AdminSshSigningKey, WriteSshSigningKey, ReadSshSigningKey},
}

var SCOPE_TO_SUB_SCOPE = map[Permission][]Permission{
	Repo:                    {RepoStatus, RepoDeployment, PublicRepo, RepoInvite, SecurityEvents},
	WritePackages:           {ReadPackages},
	AdminOrg:                {WriteOrg, ReadOrg, ManageRunnersOrg},
	WriteOrg:                {ReadOrg},
	AdminPublicKey:          {WritePublicKey, ReadPublicKey},
	WritePublicKey:          {ReadPublicKey},
	AdminRepoHook:           {WriteRepoHook, ReadRepoHook},
	WriteRepoHook:           {ReadRepoHook},
	User:                    {ReadUser, UserEmail, UserFollow},
	WriteDiscussion:         {ReadDiscussion},
	AdminEnterprise:         {ManageRunnersEnterprise, ManageBillingEnterprise, ReadEnterprise},
	ManageBillingEnterprise: {ReadEnterprise},
	AuditLog:                {ReadAuditLog},
	Codespace:               {CodespaceSecrets},
	Copilot:                 {ManageBillingCopilot},
	Project:                 {ReadProject},
	AdminGpgKey:             {WriteGpgKey, ReadGpgKey},
	WriteGpgKey:             {ReadGpgKey},
	AdminSshSigningKey:      {WriteSshSigningKey, ReadSshSigningKey},
	WriteSshSigningKey:      {ReadSshSigningKey},
}

func hasPrivateRepoAccess(scopes map[Permission]bool) bool {
	return scopes[Repo]
}

func processScopes(headerScopesSlice []analyzers.Permission) map[Permission]bool {
	allScopes := make(map[Permission]bool)
	for _, scope := range headerScopesSlice {
		allScopes[StringToPermission[scope.Value]] = true
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

func AnalyzeClassicToken(client *gh.Client, meta *common.TokenMetadata) (*common.SecretInfo, error) {
	// Convert OauthScopes to have hierarchical permissions.
	meta.OauthScopes = oauthScopesToPermissions(meta.OauthScopes...)
	scopes := processScopes(meta.OauthScopes)

	var repos []*gh.Repository
	if hasPrivateRepoAccess(scopes) {
		var err error
		repos, err = common.GetAllReposForUser(client)
		if err != nil {
			return nil, err
		}
	}

	gists, err := common.GetAllGistsForUser(client)
	if err != nil {
		return nil, err
	}

	return &common.SecretInfo{
		Metadata: meta,
		Repos:    repos,
		Gists:    gists,
	}, nil
}

func filterPrivateRepoScopes(scopes map[Permission]bool) []Permission {
	var intersection []Permission
	privateScopes := []Permission{Repo, RepoStatus, RepoDeployment, RepoInvite, SecurityEvents, AdminRepoHook, WriteRepoHook, ReadRepoHook}

	for _, privScope := range privateScopes {
		if scopes[privScope] {
			intersection = append(intersection, privScope)
		}
	}
	return intersection
}

func PrintClassicToken(cfg *config.Config, info *common.SecretInfo) {
	scopes := processScopes(info.Metadata.OauthScopes)
	if len(scopes) == 0 {
		color.Red("[x] Classic Token has no scopes")
	} else {
		printClassicGHPermissions(scopes, cfg.ShowAll)
	}

	privateScopes := filterPrivateRepoScopes(scopes)
	if hasPrivateRepoAccess(scopes) {
		color.Green("[!] Token has scope(s) for both public and private repositories. Here's a list of all accessible repositories:")
		common.PrintGitHubRepos(info.Repos)
	} else if len(privateScopes) > 0 {
		color.Yellow("[!] Token has scope(s) useful for accessing both public and private repositories.\n    However, without the `repo` scope, we cannot enumerate or access code from private repos.\n    Review the permissions associated with the following scopes for more details: %v", joinPermissions(privateScopes))
	} else if scopes[PublicRepo] {
		color.Yellow("[i] Token is scoped to only public repositories. See https://github.com/%v?tab=repositories", *info.Metadata.User.Login)
	} else {
		color.Red("[x] Token does not appear scoped to any specific repositories.")
	}
	common.PrintGists(info.Gists, cfg.ShowAll)
}

func joinPermissions(perms []Permission) string {
	var permStrings []string
	for _, perm := range perms {
		permStr, err := perm.ToString()
		if err != nil {
			panic(err)
		}
		permStrings = append(permStrings, permStr)
	}
	return strings.Join(permStrings, ", ")
}

func scopeFormatter(scope Permission, checked bool, indentation int) (string, string) {
	scopeStr, err := scope.ToString()
	if err != nil {
		panic(err)
	}
	if indentation != 0 {
		scopeStr = strings.Repeat("  ", indentation) + scopeStr
	}
	if checked {
		return color.GreenString(scopeStr), color.GreenString("true")
	}
	return scopeStr, "false"
}

func printClassicGHPermissions(scopes map[Permission]bool, showAll bool) {
	scopeCount := 0
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Scope", "In-Scope"})

	filteredScopes := make([][]Permission, 0)
	for _, scopeSlice := range SCOPE_ORDER {
		for _, scope := range scopeSlice {
			if scopes[scope] {
				filteredScopes = append(filteredScopes, scopeSlice)
				break
			}
		}
	}

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

						scopeStr, err := scope.ToString()
						if err != nil {
							panic(err)
						}
						t.AppendRow([]any{scopeStr, "----"})
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

// oauthScopesToPermissions takes a list of scopes and returns a slice of
// permissions for it. If the scope has implied permissions, they are included
// as children of the parent scope, and both the parent and children are
// returned in the slice.
func oauthScopesToPermissions(scopes ...analyzers.Permission) []analyzers.Permission {
	allPermissions := make([]analyzers.Permission, 0, len(scopes))
	for _, scope := range scopes {
		allPermissions = append(allPermissions, oauthScopeToPermissions(scope.Value)...)
	}
	return allPermissions
}

// oauthScopeToPermissions takes a given scope and returns a slice of
// permissions for it. If the scope has implied permissions, they are included
// as children of the parent scope, and both the parent and children are
// returned in the slice.
func oauthScopeToPermissions(scope string) []analyzers.Permission {
	parent := analyzers.Permission{Value: scope}
	perms := []analyzers.Permission{parent}
	subScopes, ok := func() ([]Permission, bool) {
		id, err := PermissionFromString(scope)
		if err != nil {
			return nil, false
		}
		subScopes, ok := SCOPE_TO_SUB_SCOPE[id]
		return subScopes, ok
	}()
	if !ok {
		// No sub-scopes, so the only permission is itself.
		return perms
	}
	// Add all the children to the list of permissions.
	for _, subScope := range subScopes {
		subScope, _ := subScope.ToString()
		perms = append(perms, analyzers.Permission{
			Value:  subScope,
			Parent: &parent,
		})
	}
	return perms
}
