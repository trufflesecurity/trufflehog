package github

import (
	"fmt"
	"net/http"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v63/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

const cloudEndpoint = "https://api.github.com"

type connector interface {
	ApiClient() *github.Client
	Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error)
	HttpClient() *http.Client
	IsGithubEnterprise() bool
	InstallationClient() *github.Client
}

func newConnector(source *Source) (connector, error) {
	apiEndpoint := source.conn.Endpoint
	if len(apiEndpoint) == 0 || endsWithGithub.MatchString(apiEndpoint) {
		apiEndpoint = cloudEndpoint
	}

	switch cred := source.conn.GetCredential().(type) {
	case *sourcespb.GitHub_GithubApp:
		return newAppConnector(apiEndpoint, cred.GithubApp)
	case *sourcespb.GitHub_BasicAuth:
		return newBasicAuthConnector(apiEndpoint, cred.BasicAuth)
	case *sourcespb.GitHub_Token:
		return newTokenConnector(apiEndpoint, cred.Token, source.handleRateLimit)
	case *sourcespb.GitHub_Unauthenticated:
		return newUnauthenticatedConnector(apiEndpoint)
	default:
		return nil, fmt.Errorf("unknown connection type")
	}
}
