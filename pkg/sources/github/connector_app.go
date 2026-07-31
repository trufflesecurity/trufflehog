package github

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"

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
	installationClient *github.Client
	installationID     int64
	appID              int64
	appPrivateKey      []byte
	apiEndpoint        string

	mu sync.RWMutex
	// clientsByInstallationID is scoped to this connector/source run and is
	// bounded by the installations touched while scanning.
	clientsByInstallationID map[int64]*appInstallationClients

	// repoInstallationMap maps repo clone URLs to their owning installation
	// ID for repos discovered from non-default installations. Clone checks
	// this map to use the correct installation token.
	repoInstallationMap map[string]int64
}

type appInstallationClients struct {
	apiClient     *github.Client
	graphqlClient *githubv4.Client
}

var _ Connector = (*appConnector)(nil)

const githubHTTPTimeoutSeconds = 60

func NewAppConnector(ctx context.Context, apiEndpoint string, app *credentialspb.GitHubApp) (Connector, error) {
	installationID, err := strconv.ParseInt(app.InstallationId, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("could not parse app installation ID %q: %w", app.InstallationId, err)
	}

	appID, err := strconv.ParseInt(app.AppId, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("could not parse app ID %q: %w", app.AppId, err)
	}

	installationTransport, err := newAppsTransport(apiEndpoint, appID, []byte(app.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("could not create installation client transport: %w", err)
	}
	installationClient, err := newGitHubClientWithTransport(apiEndpoint, installationTransport)
	if err != nil {
		return nil, fmt.Errorf("could not create installation client: %w", err)
	}

	connector := &appConnector{
		installationClient:      installationClient,
		installationID:          installationID,
		appID:                   appID,
		appPrivateKey:           []byte(app.PrivateKey),
		apiEndpoint:             apiEndpoint,
		clientsByInstallationID: make(map[int64]*appInstallationClients),
		repoInstallationMap:     make(map[string]int64),
	}

	if _, err := connector.APIClientForInstallation(installationID); err != nil {
		return nil, fmt.Errorf("could not create API client for configured installation: %w", err)
	}

	if _, err := connector.graphqlClientForInstallation(ctx, installationID); err != nil {
		return nil, fmt.Errorf("error creating GraphQL client: %w", err)
	}

	return connector, nil
}

func (c *appConnector) APIClient() *github.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if clients := c.clientsByInstallationID[c.installationID]; clients != nil {
		return clients.apiClient
	}
	return nil
}

func (c *appConnector) APIClientForRepo(repoURL string) (*github.Client, error) {
	installID, _ := c.installationIDForRepo(repoURL)
	return c.APIClientForInstallation(installID)
}

func (c *appConnector) GraphQLClientForRepo(ctx context.Context, repoURL string) (*githubv4.Client, error) {
	installID, _ := c.installationIDForRepo(repoURL)
	return c.graphqlClientForInstallation(ctx, installID)
}

func (c *appConnector) graphqlClientForInstallation(ctx context.Context, installID int64) (*githubv4.Client, error) {
	c.mu.RLock()
	if clients := c.clientsByInstallationID[installID]; clients != nil && clients.graphqlClient != nil {
		client := clients.graphqlClient
		c.mu.RUnlock()
		return client, nil
	}
	c.mu.RUnlock()

	apiClient, err := c.APIClientForInstallation(installID)
	if err != nil {
		return nil, err
	}
	client, err := createGraphqlClient(ctx, apiClient.Client(), c.apiEndpoint)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	clients := c.clientsForInstallationLocked(installID)
	if clients.graphqlClient != nil {
		return clients.graphqlClient, nil
	}
	if clients.apiClient == nil {
		clients.apiClient = apiClient
	}
	clients.graphqlClient = client
	return client, nil
}

func (c *appConnector) Clone(ctx context.Context, repoURL string, args ...string) (string, *gogit.Repository, error) {
	installID, _ := c.installationIDForRepo(repoURL)

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

// installationIDForRepo returns the mapped installation ID for repoURL. When no
// mapping exists, it falls back to the configured installation and returns false.
func (c *appConnector) installationIDForRepo(repoURL string) (int64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if id, ok := c.repoInstallationMap[repoURL]; ok {
		return id, true
	}
	return c.installationID, false
}

func (c *appConnector) hasRepoInstallation(repoURL string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, ok := c.repoInstallationMap[repoURL]
	return ok
}

// setRepoInstallation records which installation owns a repo and its derived
// wiki URL so Clone uses the correct installation token for cross-org repos.
func (c *appConnector) setRepoInstallation(repoURL string, installationID int64) {
	c.setRepoInstallationForWiki(repoURL, installationID, wikiCloneURLForRepo)
}

// ensureRepoInstallation maps a repo to the default installation unless an
// installation already claims it. Used for repos discovered outside
// installation listings (e.g. org members' personal repos), which no
// installation owns but which the default installation token can still
// access when they are public. The check and set happen under one lock so a
// concurrent mapping to a real installation is never overwritten.
func (c *appConnector) ensureRepoInstallation(repoURL, repoName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.repoInstallationMap[repoURL]; ok {
		return
	}
	c.repoInstallationMap[repoURL] = c.installationID
	if wikiURL, ok := wikiCloneURLForRepoName(repoURL, repoName); ok {
		if _, taken := c.repoInstallationMap[wikiURL]; !taken {
			c.repoInstallationMap[wikiURL] = c.installationID
		}
	}
}

func (c *appConnector) setRepoInstallationForRepoName(repoURL, repoName string, installationID int64) {
	c.setRepoInstallationForWiki(repoURL, installationID, func(repoURL string) (string, bool) {
		return wikiCloneURLForRepoName(repoURL, repoName)
	})
}

func (c *appConnector) setRepoInstallationForWiki(repoURL string, installationID int64, wikiURLForRepo func(string) (string, bool)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.repoInstallationMap[repoURL] = installationID
	if wikiURL, ok := wikiURLForRepo(repoURL); ok {
		c.repoInstallationMap[wikiURL] = installationID
	}
}

func (c *appConnector) GraphQLClient() *githubv4.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if clients := c.clientsByInstallationID[c.installationID]; clients != nil {
		return clients.graphqlClient
	}
	return nil
}

func (c *appConnector) InstallationClient() *github.Client {
	return c.installationClient
}

// APIClientForInstallation creates a GitHub API client scoped to a specific
// installation. This is needed when a GitHub App is installed across multiple
// orgs — each org's API calls must use that org's installation token to get
// proper IP allowlist bypass and permission scoping.
func (c *appConnector) APIClientForInstallation(installationID int64) (*github.Client, error) {
	c.mu.RLock()
	if clients := c.clientsByInstallationID[installationID]; clients != nil && clients.apiClient != nil {
		client := clients.apiClient
		c.mu.RUnlock()
		return client, nil
	}
	c.mu.RUnlock()

	client, err := c.createAPIClientForInstallation(installationID)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	clients := c.clientsForInstallationLocked(installationID)
	if clients.apiClient != nil {
		return clients.apiClient, nil
	}
	clients.apiClient = client
	return client, nil
}

func (c *appConnector) clientsForInstallationLocked(installationID int64) *appInstallationClients {
	clients := c.clientsByInstallationID[installationID]
	if clients == nil {
		clients = &appInstallationClients{}
		c.clientsByInstallationID[installationID] = clients
	}
	return clients
}

func (c *appConnector) createAPIClientForInstallation(installationID int64) (*github.Client, error) {
	appsTransport, err := newAppsTransport(c.apiEndpoint, c.appID, c.appPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("could not create app transport for installation %d: %w", installationID, err)
	}

	transport := ghinstallation.NewFromAppsTransport(appsTransport, installationID)
	transport.BaseURL = c.apiEndpoint

	client, err := newGitHubClientWithTransport(c.apiEndpoint, transport)
	if err != nil {
		return nil, fmt.Errorf("could not create API client for installation %d: %w", installationID, err)
	}
	return client, nil
}

func newAppsTransport(apiEndpoint string, appID int64, privateKey []byte) (*ghinstallation.AppsTransport, error) {
	httpClient := common.RetryableHTTPClientTimeout(githubHTTPTimeoutSeconds)
	appsTransport, err := ghinstallation.NewAppsTransport(httpClient.Transport, appID, privateKey)
	if err != nil {
		return nil, err
	}
	appsTransport.BaseURL = apiEndpoint
	return appsTransport, nil
}

func newGitHubClientWithTransport(apiEndpoint string, transport http.RoundTripper) (*github.Client, error) {
	httpClient := common.RetryableHTTPClientTimeout(githubHTTPTimeoutSeconds)
	httpClient.Transport = transport
	return github.NewClient(httpClient).WithEnterpriseURLs(apiEndpoint, apiEndpoint)
}
