package github

import (
	"fmt"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v67/github"
	"github.com/shurcooL/githubv4"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type unauthenticatedConnector struct {
	apiClient     *github.Client
	graphqlClient *githubv4.Client

	clonePath string
}

var _ Connector = (*unauthenticatedConnector)(nil)

func NewUnauthenticatedConnector(ctx context.Context, apiEndpoint, clonePath string) (Connector, error) {
	const httpTimeoutSeconds = 60
	httpClient := common.RetryableHTTPClientTimeout(int64(httpTimeoutSeconds))
	apiClient, err := createAPIClient(ctx, httpClient, apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("could not create API client: %w", err)
	}

	graphqlClient, err := createGraphqlClient(ctx, httpClient, apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("error creating GraphQL client: %w", err)
	}

	return &unauthenticatedConnector{
		apiClient:     apiClient,
		graphqlClient: graphqlClient,
		clonePath:     clonePath,
	}, nil
}

func (c *unauthenticatedConnector) APIClient() *github.Client {
	return c.apiClient
}

func (c *unauthenticatedConnector) Clone(ctx context.Context, repoURL string, args ...string) (string, *gogit.Repository, error) {
	return git.CloneRepoUsingUnauthenticated(ctx, repoURL, c.clonePath, args...)
}

func (c *unauthenticatedConnector) GraphQLClient() *githubv4.Client {
	return c.graphqlClient
}
