package github

import (
	"fmt"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v63/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type unauthenticatedConnector struct {
	apiClient          *github.Client
	isGitHubEnterprise bool
}

var _ connector = (*unauthenticatedConnector)(nil)

func newUnauthenticatedConnector(apiEndpoint string) (*unauthenticatedConnector, error) {
	httpClient := common.RetryableHTTPClientTimeout(60)
	apiClient, err := createGitHubClient(httpClient, apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("could not create API client: %w", err)
	}
	return &unauthenticatedConnector{
		apiClient:          apiClient,
		isGitHubEnterprise: !strings.EqualFold(apiEndpoint, cloudEndpoint),
	}, nil
}

func (c *unauthenticatedConnector) ApiClient() *github.Client {
	return c.apiClient
}

func (c *unauthenticatedConnector) Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error) {
	return git.CloneRepoUsingUnauthenticated(ctx, repoURL)
}

func (c *unauthenticatedConnector) IsGithubEnterprise() bool {
	// At the time of this writing, this method is not called anywhere, so if you start calling it and something looks
	// wrong don't assume that this implementation is correct. (It is implemented here because the interface requires
	// it, but the only code path that checks for GHE uses a different implementation of this interface.)
	return c.isGitHubEnterprise
}

func (c *unauthenticatedConnector) InstallationClient() *github.Client {
	return nil
}
