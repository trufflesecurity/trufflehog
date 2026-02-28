package github

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v67/github"
	"github.com/shurcooL/githubv4"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type appConnector struct {
	apiClient          *github.Client
	graphqlClient      *githubv4.Client
	installationClient *github.Client
	installationID     int64
	appsTransport      *ghinstallation.AppsTransport
	apiEndpoint        string

	// repoInstallationMap maps repo clone URLs to their owning installation
	// ID for repos discovered from non-default installations. Clone checks
	// this map to use the correct installation token.
	repoInstallationMap map[string]int64
}

var _ Connector = (*appConnector)(nil)

func NewAppConnector(ctx context.Context, apiEndpoint string, app *credentialspb.GitHubApp) (Connector, error) {
	installationID, err := strconv.ParseInt(app.InstallationId, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("could not parse app installation ID %q: %w", app.InstallationId, err)
	}

	appID, err := strconv.ParseInt(app.AppId, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("could not parse app ID %q: %w", appID, err)
	}

	const httpTimeoutSeconds = 60
	httpClient := common.RetryableHTTPClientTimeout(int64(httpTimeoutSeconds))

	installationTransport, err := ghinstallation.NewAppsTransport(
		httpClient.Transport,
		appID,
		[]byte(app.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("could not create installation client transport: %w", err)
	}
	installationTransport.BaseURL = apiEndpoint

	installationHttpClient := common.RetryableHTTPClientTimeout(60)
	installationHttpClient.Transport = installationTransport
	installationClient, err := github.NewClient(installationHttpClient).WithEnterpriseURLs(apiEndpoint, apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("could not create installation client: %w", err)
	}

	apiTransport, err := ghinstallation.New(
		httpClient.Transport,
		appID,
		installationID,
		[]byte(app.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("could not create API client transport: %w", err)
	}
	apiTransport.BaseURL = apiEndpoint

	httpClient.Transport = apiTransport
	apiClient, err := github.NewClient(httpClient).WithEnterpriseURLs(apiEndpoint, apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("could not create API client: %w", err)
	}

	graphqlClient, err := createGraphqlClient(ctx, httpClient, apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("error creating GraphQL client: %w", err)
	}

	return &appConnector{
		apiClient:           apiClient,
		graphqlClient:       graphqlClient,
		installationClient:  installationClient,
		installationID:      installationID,
		appsTransport:       installationTransport,
		apiEndpoint:         apiEndpoint,
		repoInstallationMap: make(map[string]int64),
	}, nil
}

func (c *appConnector) APIClient() *github.Client {
	return c.apiClient
}

func (c *appConnector) Clone(ctx context.Context, repoURL string, args ...string) (string, *gogit.Repository, error) {
	installID := c.installationID
	if id, ok := c.repoInstallationMap[repoURL]; ok {
		installID = id
	}

	// TODO: Check rate limit for this call.
	token, _, err := c.installationClient.Apps.CreateInstallationToken(
		ctx,
		installID,
		&github.InstallationTokenOptions{})
	if err != nil {
		return "", nil, fmt.Errorf("could not create installation token for installation %d: %w", installID, err)
	}

	return git.CloneRepoUsingToken(ctx, token.GetToken(), repoURL, "", "x-access-token", true, args...)
}

// SetRepoInstallation records which installation owns a repo so that Clone
// uses the correct installation token for cross-org repos.
func (c *appConnector) SetRepoInstallation(repoURL string, installationID int64) {
	c.repoInstallationMap[repoURL] = installationID
	if strings.HasSuffix(repoURL, ".git") {
		wikiURL := strings.TrimSuffix(repoURL, ".git") + ".wiki.git"
		c.repoInstallationMap[wikiURL] = installationID
	}
}

func (c *appConnector) GraphQLClient() *githubv4.Client {
	return c.graphqlClient
}

func (c *appConnector) InstallationClient() *github.Client {
	return c.installationClient
}

// APIClientForInstallation creates a GitHub API client scoped to a specific
// installation. This is needed when a GitHub App is installed across multiple
// orgs — each org's API calls must use that org's installation token to get
// proper IP allowlist bypass and permission scoping.
func (c *appConnector) APIClientForInstallation(installationID int64) (*github.Client, error) {
	transport := ghinstallation.NewFromAppsTransport(c.appsTransport, installationID)
	transport.BaseURL = c.apiEndpoint

	httpClient := common.RetryableHTTPClientTimeout(60)
	httpClient.Transport = transport

	client, err := github.NewClient(httpClient).WithEnterpriseURLs(c.apiEndpoint, c.apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("could not create API client for installation %d: %w", installationID, err)
	}
	return client, nil
}
