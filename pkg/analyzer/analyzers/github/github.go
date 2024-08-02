package github

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	gh "github.com/google/go-github/v63/github"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github/classic"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github/finegrained"
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

func secretInfoToAnalyzerResult(info *common.SecretInfo) *analyzers.AnalyzerResult {
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
	}
	return classic.AnalyzeClassicToken(client, md)
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
		finegrained.PrintFineGrainedToken(cfg, info)
		return
	}
	classic.PrintClassicToken(cfg, info)
}
