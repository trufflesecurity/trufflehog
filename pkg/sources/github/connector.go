package github

import (
	"fmt"
	"net/http"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v62/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

type connector interface {
	ApiClient() *github.Client
	Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error)
	IsGithubEnterprise() bool
	HttpClient() *http.Client
	ListAppInstallations(ctx context.Context) ([]*github.Installation, error)
}

func newConnector(connection *sourcespb.GitHub) (connector, error) {
	apiEndpoint := connection.Endpoint
	if len(apiEndpoint) == 0 || endsWithGithub.MatchString(apiEndpoint) {
		apiEndpoint = cloudEndpoint
	}

	switch cred := connection.GetCredential().(type) {
	case *sourcespb.GitHub_GithubApp:
		return newAppConnector(apiEndpoint, cred.GithubApp)
	case *sourcespb.GitHub_Unauthenticated:
		return newUnauthenticatedConnector(apiEndpoint)
	default:
		return nil, fmt.Errorf("unknown connection type")
	}
}
