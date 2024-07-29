package github

import (
	"fmt"
	"net/http"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v62/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type connector interface {
	ApiClient() *github.Client
	Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error)
	IsGithubEnterprise() bool
	HttpClient() *http.Client
	ListAppInstallations() ([]*github.Installation, error)
}

func newConnector(connection *sourcespb.GitHub) (connector, error) {
	apiEndpoint := connection.Endpoint
	if len(apiEndpoint) == 0 || endsWithGithub.MatchString(apiEndpoint) {
		apiEndpoint = cloudEndpoint
	}

	switch _ := connection.GetCredential().(type) {
	case *sourcespb.GitHub_Unauthenticated:
		return newUnauthenticatedConnector(apiEndpoint)
	default:
		return nil, fmt.Errorf("unknown connection type")
	}
}

type unauthenticatedConnector struct {
	httpClient *http.Client
	apiClient  *github.Client
}

var _ connector = (*unauthenticatedConnector)(nil)

func newUnauthenticatedConnector(apiEndpoint string) (connector, error) {
	httpClient := common.RetryableHTTPClientTimeout(60)
	apiClient, err := createGitHubClient(httpClient, apiEndpoint)
	if err != nil {
		return nil, err
	}
	return unauthenticatedConnector{
		httpClient: httpClient,
		apiClient:  apiClient,
	}, nil
}

func (c unauthenticatedConnector) ApiClient() *github.Client {
	return c.apiClient
}

func (c unauthenticatedConnector) Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error) {
	return git.CloneRepoUsingUnauthenticated(ctx, repoURL)
}

func (c unauthenticatedConnector) IsGithubEnterprise() bool {
	return false
}

func (c unauthenticatedConnector) HttpClient() *http.Client {
	return c.httpClient
}

func (c unauthenticatedConnector) ListAppInstallations() ([]*github.Installation, error) {
	return nil, nil
}
