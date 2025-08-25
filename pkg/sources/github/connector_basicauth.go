package github

import (
	"fmt"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v67/github"
	"github.com/shurcooL/githubv4"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type basicAuthConnector struct {
	apiClient     *github.Client
	graphqlClient *githubv4.Client
	username      string
	password      string
	clonePath     string
}

var _ Connector = (*basicAuthConnector)(nil)

func NewBasicAuthConnector(ctx context.Context, apiEndpoint, clonePath string, cred *credentialspb.BasicAuth) (Connector, error) {
	const httpTimeoutSeconds = 60
	httpClient := common.RetryableHTTPClientTimeout(int64(httpTimeoutSeconds))
	httpClient.Transport = &github.BasicAuthTransport{
		Username: cred.Username,
		Password: cred.Password,
	}

	apiClient, err := createAPIClient(ctx, httpClient, apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("could not create API client: %w", err)
	}

	graphqlClient, err := createGraphqlClient(ctx, httpClient, apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("error creating GraphQL client: %w", err)
	}

	return &basicAuthConnector{
		apiClient:     apiClient,
		graphqlClient: graphqlClient,
		username:      cred.Username,
		password:      cred.Password,
		clonePath:     clonePath,
	}, nil
}

func (c *basicAuthConnector) APIClient() *github.Client {
	return c.apiClient
}

func (c *basicAuthConnector) Clone(ctx context.Context, repoURL string, args ...string) (string, *gogit.Repository, error) {
	return git.CloneRepoUsingToken(ctx, c.password, repoURL, c.clonePath, c.username, true, args...)
}

func (c *basicAuthConnector) GraphQLClient() *githubv4.Client {
	return c.graphqlClient
}
