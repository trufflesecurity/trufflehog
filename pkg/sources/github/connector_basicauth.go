package github

import (
	"fmt"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v63/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type basicAuthConnector struct {
	apiClient          *github.Client
	username           string
	password           string
	isGitHubEnterprise bool
}

var _ connector = (*basicAuthConnector)(nil)

func newBasicAuthConnector(apiEndpoint string, cred *credentialspb.BasicAuth) (*basicAuthConnector, error) {
	httpClient := common.RetryableHTTPClientTimeout(60)
	httpClient.Transport = &github.BasicAuthTransport{
		Username: cred.Username,
		Password: cred.Password,
	}

	apiClient, err := createGitHubClient(httpClient, apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("could not create API client: %w", err)
	}

	return &basicAuthConnector{
		apiClient:          apiClient,
		username:           cred.Username,
		password:           cred.Password,
		isGitHubEnterprise: !strings.EqualFold(apiEndpoint, cloudEndpoint),
	}, nil
}

func (c *basicAuthConnector) ApiClient() *github.Client {
	return c.apiClient
}

func (c *basicAuthConnector) Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error) {
	return git.CloneRepoUsingToken(ctx, c.password, repoURL, c.username)
}

func (c *basicAuthConnector) IsGithubEnterprise() bool {
	// At the time of this writing, this method is not called anywhere, so if you start calling it and something looks
	// wrong don't assume that this implementation is correct. (It is implemented here because the interface requires
	// it, but the only code path that checks for GHE uses a different implementation of this interface.)
	return c.isGitHubEnterprise
}

func (c *basicAuthConnector) InstallationClient() *github.Client {
	return nil
}
