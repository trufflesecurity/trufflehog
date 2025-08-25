package github

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v67/github"
	"github.com/shurcooL/githubv4"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

const (
	cloudV3Endpoint      = "https://api.github.com"
	cloudGraphqlEndpoint = "https://api.github.com/graphql" // https://docs.github.com/en/graphql/guides/forming-calls-with-graphql#the-graphql-endpoint
)

// Connector abstracts over the authenticated ways to interact with GitHub: cloning and API operations.
type Connector interface {
	// APIClient returns a configured GitHub client that can be used for GitHub API operations.
	APIClient() *github.Client
	// GraphQLClient returns a client that can be used for GraphQL operations.
	GraphQLClient() *githubv4.Client
	// Clone clones a repository using the configured authentication information.
	Clone(ctx context.Context, repoURL string, args ...string) (string, *gogit.Repository, error)
}

func newConnector(ctx context.Context, source *Source) (Connector, error) {
	apiEndpoint := source.conn.Endpoint
	if apiEndpoint == "" || endsWithGithub.MatchString(apiEndpoint) {
		apiEndpoint = cloudV3Endpoint
	}

	switch cred := source.conn.GetCredential().(type) {
	case *sourcespb.GitHub_GithubApp:
		log.RedactGlobally(cred.GithubApp.GetPrivateKey())
		return NewAppConnector(ctx, apiEndpoint, cred.GithubApp)
	case *sourcespb.GitHub_BasicAuth:
		log.RedactGlobally(cred.BasicAuth.GetPassword())
		return NewBasicAuthConnector(ctx, apiEndpoint, source.conn.GetClonePath(), cred.BasicAuth)
	case *sourcespb.GitHub_Token:
		log.RedactGlobally(cred.Token)
		return NewTokenConnector(ctx, apiEndpoint, cred.Token, source.conn.GetClonePath(), source.useAuthInUrl, func(c context.Context, err error) bool {
			return source.handleRateLimit(c, err)
		})
	case *sourcespb.GitHub_Unauthenticated:
		return NewUnauthenticatedConnector(ctx, apiEndpoint, source.conn.GetClonePath())
	default:
		return nil, fmt.Errorf("unknown connection type %T", source.conn.GetCredential())
	}
}

func createAPIClient(ctx context.Context, httpClient *http.Client, apiEndpoint string) (*github.Client, error) {
	ctx.Logger().V(2).Info("Creating API client", "url", apiEndpoint)

	// If we're using public GitHub, make a regular client.
	// Otherwise, make an enterprise client.
	if strings.EqualFold(apiEndpoint, cloudV3Endpoint) {
		return github.NewClient(httpClient), nil
	}

	return github.NewClient(httpClient).WithEnterpriseURLs(apiEndpoint, apiEndpoint)
}

func createGraphqlClient(ctx context.Context, client *http.Client, apiEndpoint string) (*githubv4.Client, error) {
	var graphqlEndpoint string
	if apiEndpoint == cloudV3Endpoint {
		graphqlEndpoint = cloudGraphqlEndpoint
	} else {
		// Use the root endpoint for the host.
		// https://docs.github.com/en/enterprise-server@3.11/graphql/guides/introduction-to-graphql
		parsedURL, err := url.Parse(apiEndpoint)
		if err != nil {
			return nil, fmt.Errorf("error parsing URL: %w", err)
		}

		// GitHub Enterprise uses `/api/v3` for the base. (https://github.com/google/go-github/issues/958)
		// Swap it, and anything before `/api`, with GraphQL.
		before, _ := strings.CutSuffix(parsedURL.Path, "/api/v3")
		parsedURL.Path = before + "/api/graphql"
		graphqlEndpoint = parsedURL.String()
	}

	ctx.Logger().V(2).Info("Creating GraphQL client", "url", graphqlEndpoint)

	return githubv4.NewEnterpriseClient(graphqlEndpoint, client), nil
}
