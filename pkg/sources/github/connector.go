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

	gheCloudSuffix = ".ghe.com"
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

// isGHECloud returns true if the endpoint is a GHE.com instance
// (GHEC with data residency). GHE.com uses the same root-level API layout as
// api.github.com, NOT the GHES /api/v3/ layout.
//
// Examples:
//
//	https://api.company.ghe.com   -> true
//	https://company.ghe.com       -> true  (web URL; user might pass this)
//	https://github.mycompany.com -> false (GHES)
//	https://api.github.com       -> false (regular github.com)
func isGHECloud(endpoint string) bool {
	u, err := url.Parse(strings.TrimRight(endpoint, "/"))
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(u.Hostname()), gheCloudSuffix)
}

// normalizeGHECloudAPIEndpoint ensures the endpoint points to the API subdomain
// with a trailing slash (required by go-github's BaseURL).
//
// On GHE.com the web UI lives at SUBDOMAIN.ghe.com while the API lives at
// api.SUBDOMAIN.ghe.com. Users may pass either form.
//
//	https://company.ghe.com       -> https://api.company.ghe.com/
//	https://company.ghe.com/      -> https://api.company.ghe.com/
//	https://api.company.ghe.com   -> https://api.company.ghe.com/
//	https://api.company.ghe.com/  -> https://api.company.ghe.com/
func normalizeGHECloudAPIEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(strings.TrimRight(endpoint, "/"))
	if err != nil {
		return "", fmt.Errorf("invalid GHE.com endpoint URL: %w", err)
	}

	host := u.Hostname()
	port := u.Port()

	// If user passed the web URL (company.ghe.com), prepend "api."
	if !strings.HasPrefix(strings.ToLower(host), "api.") {
		host = "api." + host
	}

	if port != "" {
		u.Host = host + ":" + port
	} else {
		u.Host = host
	}

	// go-github requires a trailing slash on BaseURL.
	u.Path = "/"

	return u.String(), nil
}

// createGHECloudClient creates a go-github client configured for GHE.com.
// GHE.com serves its REST API at the root of api.SUBDOMAIN.ghe.com (same
// layout as api.github.com), so we must NOT use WithEnterpriseURLs which
// would append /api/v3/.
func createGHECloudClient(httpClient *http.Client, apiEndpoint string) (*github.Client, error) {
	apiURL, err := normalizeGHECloudAPIEndpoint(apiEndpoint)
	if err != nil {
		return nil, err
	}

	parsedURL, err := url.Parse(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GHE.com API URL: %w", err)
	}

	client := github.NewClient(httpClient)
	client.BaseURL = parsedURL
	client.UploadURL = parsedURL
	return client, nil
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
	if strings.EqualFold(apiEndpoint, cloudV3Endpoint) {
		return github.NewClient(httpClient), nil
	}

	// GHE.com (GHEC with data residency) serves its API at the root level
	// (like api.github.com), NOT under /api/v3/.
	if isGHECloud(apiEndpoint) {
		return createGHECloudClient(httpClient, apiEndpoint)
	}

	// GHES (self-hosted) — WithEnterpriseURLs appends /api/v3/ and /api/uploads/.
	return github.NewClient(httpClient).WithEnterpriseURLs(apiEndpoint, apiEndpoint)
}

func createGraphqlClient(ctx context.Context, client *http.Client, apiEndpoint string) (*githubv4.Client, error) {
	var graphqlEndpoint string
	switch {
	case apiEndpoint == cloudV3Endpoint:
		graphqlEndpoint = cloudGraphqlEndpoint

	case isGHECloud(apiEndpoint):
		// GHE.com: GraphQL lives at the root level, same as api.github.com.
		// https://api.SUBDOMAIN.ghe.com/graphql
		apiURL, err := normalizeGHECloudAPIEndpoint(apiEndpoint)
		if err != nil {
			return nil, fmt.Errorf("error normalizing GHE.com endpoint: %w", err)
		}
		graphqlEndpoint = strings.TrimRight(apiURL, "/") + "/graphql"

	default:
		// GHES: GraphQL lives under /api/graphql.
		// https://docs.github.com/en/enterprise-server@3.11/graphql/guides/introduction-to-graphql
		parsedURL, err := url.Parse(apiEndpoint)
		if err != nil {
			return nil, fmt.Errorf("error parsing URL: %w", err)
		}

		// GitHub Enterprise Server uses `/api/v3` for the base. (https://github.com/google/go-github/issues/958)
		// Swap it, and anything before `/api`, with GraphQL.
		before, _ := strings.CutSuffix(parsedURL.Path, "/api/v3")
		parsedURL.Path = before + "/api/graphql"
		graphqlEndpoint = parsedURL.String()
	}

	ctx.Logger().V(2).Info("Creating GraphQL client", "url", graphqlEndpoint)

	return githubv4.NewEnterpriseClient(graphqlEndpoint, client), nil
}
