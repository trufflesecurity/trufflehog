package github

import (
	"net/http"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v63/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type unauthenticatedConnector struct {
	httpClient *http.Client
	apiClient  *github.Client
	enumerate  func(ctx context.Context)
}

var _ connector = (*unauthenticatedConnector)(nil)

func newUnauthenticatedConnector(
	apiEndpoint string,
	enumerate func(ctx context.Context)) (*unauthenticatedConnector, error) {

	httpClient := common.RetryableHTTPClientTimeout(60)
	apiClient, err := createGitHubClient(httpClient, apiEndpoint)
	if err != nil {
		return nil, err
	}
	return &unauthenticatedConnector{
		httpClient: httpClient,
		apiClient:  apiClient,
		enumerate:  enumerate,
	}, nil
}

func (c unauthenticatedConnector) ApiClient() *github.Client {
	return c.apiClient
}

func (c unauthenticatedConnector) Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error) {
	return git.CloneRepoUsingUnauthenticated(ctx, repoURL)
}

func (c unauthenticatedConnector) Enumerate(ctx context.Context) error {
	c.enumerate(ctx)
	return nil
}

func (c unauthenticatedConnector) IsGithubEnterprise() bool {
	return false
}

func (c unauthenticatedConnector) HttpClient() *http.Client {
	return c.httpClient
}

func (c unauthenticatedConnector) InstallationClient() *github.Client {
	return nil
}
