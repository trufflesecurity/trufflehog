//go:generate generate_permissions permissions.yaml permissions.go dockerhub
package dockerhub

import (
	"errors"
	"os"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

// SecretInfo hold the information about the token generated from username and pat
type SecretInfo struct {
	User         User
	Valid        bool
	Reference    string
	Permissions  []string
	Repositories []Repository
	ExpiresIn    string
	Misc         map[string]string
}

// User hold the information about user to whom the personal access token belongs
type User struct {
	ID       string
	Username string
	Email    string
}

// Repository hold information about each repository the user can access
type Repository struct {
	ID        string
	Name      string
	Type      string
	IsPrivate bool
	StarCount int
	PullCount int
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeDockerHub
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	username, exist := credInfo["username"]
	if !exist {
		return nil, analyzers.NewAnalysisError(
			"DockerHub", "validate_credentials", "config", "", errors.New("username not found in the credentials info"),
		)
	}

	pat, exist := credInfo["pat"]
	if !exist {
		return nil, analyzers.NewAnalysisError(
			"DockerHub", "validate_credentials", "config", "", errors.New("personal access token(PAT) not found in the credentials info"),
		)
	}

	info, err := AnalyzePermissions(a.Cfg, username, pat)
	if err != nil {
		return nil, analyzers.NewAnalysisError(
			"DockerHub", "analyze_permissions", "API", "", err,
		)
	}

	return secretInfoToAnalyzerResult(info), nil
}

// AnalyzePermissions will collect all the scopes assigned to token along with resource it can access
func AnalyzePermissions(cfg *config.Config, username, pat string) (*SecretInfo, error) {
	// create the http client
	client := analyzers.NewAnalyzeClientUnrestricted(cfg) // `/user/login` is a non-safe request

	var secretInfo = &SecretInfo{}

	// try to login and get jwt token
	token, err := login(client, username, pat)
	if err != nil {
		return nil, err
	}

	if err := decodeTokenToSecretInfo(token, secretInfo); err != nil {
		return nil, err
	}

	// fetch repositories using the jwt token and translate them to secret info
	if err := fetchRepositories(client, username, token, secretInfo); err != nil {
		return nil, err
	}

	// return secret info
	return secretInfo, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, username, pat string) {
	info, err := AnalyzePermissions(cfg, username, pat)
	if err != nil {
		// just print the error in cli and continue as a partial success
		color.Red("[x] Error : %s", err.Error())
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	if info.Valid {
		color.Green("[!] Valid DockerHub Credentials\n\n")
		// print user information
		printUser(info.User)
		// print permissions
		printPermissions(info.Permissions)
		// print repositories
		printRepositories(info.Repositories)

		color.Yellow("\n[i] Expires: %s", info.ExpiresIn)
	}
}

// secretInfoToAnalyzerResult translate secret info to Analyzer Result
func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeDockerHub,
		Metadata:     map[string]any{"Valid_Key": info.Valid},
		Bindings:     make([]analyzers.Binding, len(info.Repositories)),
	}

	// extract information to create bindings and append to result bindings
	for _, repo := range info.Repositories {
		binding := analyzers.Binding{
			Resource: analyzers.Resource{
				Name:               repo.Name,
				FullyQualifiedName: repo.ID,
				Type:               repo.Type,
				Metadata: map[string]any{
					"is_private": repo.IsPrivate,
					"pull_count": repo.PullCount,
					"star_count": repo.StarCount,
				},
			},
			Permission: analyzers.Permission{
				// as all permissions are against repo, we assign the highest available permission
				Value: assignHighestPermission(info.Permissions),
			},
		}

		result.Bindings = append(result.Bindings, binding)
	}

	return &result
}

// cli print functions
func printUser(user User) {
	color.Green("\n[i] User:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "Username", "Email"})
	t.AppendRow(table.Row{color.GreenString(user.ID), color.GreenString(user.Username), color.GreenString(user.Email)})
	t.Render()
}

func printPermissions(permissions []string) {
	color.Yellow("[i] Permissions:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Permission"})
	for _, permission := range permissions {
		t.AppendRow(table.Row{color.GreenString(permission)})
	}
	t.Render()
}

func printRepositories(repos []Repository) {
	color.Green("\n[i] Repositories:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Type", "ID(username/repo/repo_type/repo_name)", "Name", "Is Private", "Pull Count", "Star Count"})
	for _, repo := range repos {
		t.AppendRow(table.Row{color.GreenString(repo.Type), color.GreenString(repo.ID), color.GreenString(repo.Name),
			color.GreenString("%t", repo.IsPrivate), color.GreenString("%d", repo.PullCount), color.GreenString("%d", repo.StarCount)})
	}
	t.Render()
}
