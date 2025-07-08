package github

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	gh "github.com/google/go-github/v67/github"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github/classic"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github/finegrained"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeGitHub }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	info, err := AnalyzePermissions(a.Cfg, credInfo["key"])
	if err != nil {
		return nil, err
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *common.SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}
	result := &analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeGitHub,
		Metadata: map[string]any{
			"owner":      info.Metadata.User.Login,
			"type":       info.Metadata.Type,
			"expiration": info.Metadata.Expiration,
		},
	}
	result.Bindings = append(result.Bindings, secretInfoToUserBindings(info)...)
	result.Bindings = append(result.Bindings, secretInfoToRepoBindings(info)...)
	result.Bindings = append(result.Bindings, secretInfoToGistBindings(info)...)
	for _, repo := range append(info.Repos, info.AccessibleRepos...) {
		if repo.Owner.GetType() != "Organization" {
			continue
		}
		name := repo.Owner.GetName()
		if name == "" {
			continue
		}
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

func secretInfoToUserBindings(info *common.SecretInfo) []analyzers.Binding {
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

func secretInfoToRepoBindings(info *common.SecretInfo) []analyzers.Binding {
	var perms []analyzers.Permission
	switch info.Metadata.Type {
	case common.TokenTypeClassicPAT:
		perms = info.Metadata.OauthScopes
	case common.TokenTypeFineGrainedPAT:
		fineGrainedPermissions := info.RepoAccessMap.([]finegrained.Permission)
		for _, perm := range fineGrainedPermissions {
			permName, _ := perm.ToString()
			perms = append(perms, analyzers.Permission{Value: permName})
		}
	default:
		if len(info.Metadata.OauthScopes) > 0 {
			perms = info.Metadata.OauthScopes
		}
	}

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
		bindings = append(bindings, analyzers.BindAllPermissions(resource, perms...)...)
	}
	return bindings
}

func secretInfoToGistBindings(info *common.SecretInfo) []analyzers.Binding {
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

func AnalyzePermissions(cfg *config.Config, key string) (*common.SecretInfo, error) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	client := gh.NewClient(analyzers.NewAnalyzeClient(cfg)).WithAuthToken(key)

	md, err := common.GetTokenMetadata(key, client)
	if err != nil {
		return nil, err
	}

	if md.FineGrained {
		return finegrained.AnalyzeFineGrainedToken(client, md, cfg.Shallow)
	} else {
		return classic.AnalyzeClassicToken(client, md)
	}
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
		color.Yellow("[i] Token Expiration: %v (%s remaining)", expiry, roughHumanReadableDuration(timeRemaining))
	}
	color.Yellow("[i] Token Type: %s\n\n", info.Metadata.Type)

	if info.Metadata.FineGrained {
		finegrained.PrintFineGrainedToken(cfg, info)
		return
	}
	classic.PrintClassicToken(cfg, info)
}

// roughHumanReadableDuration converts a duration into a rough estimate for
// human consumption. The larger the duration, the larger granularity is
// returned.
func roughHumanReadableDuration(d time.Duration) string {
	var gran time.Duration
	var unit string
	switch {
	case d < 1*time.Minute:
		gran = time.Second
		unit = "second"
	case d < 1*time.Hour:
		gran = time.Minute
		unit = "minute"
	case d < 24*time.Hour:
		gran = time.Hour
		unit = "hour"
	case d < 4*7*24*time.Hour:
		gran = 24 * time.Hour
		unit = "day"
	case d < 3*4*7*24*time.Hour:
		gran = 7 * 24 * time.Hour
		unit = "week"
	case d < 5*365*24*time.Hour:
		gran = 365 * 24 * time.Hour
		unit = "month"
	default:
		gran = 365 * 24 * time.Hour
		unit = "year"
	}
	num := d.Round(gran) / gran
	if num != 1 {
		unit += "s"
	}
	return fmt.Sprintf("%d %s", num, unit)
}
