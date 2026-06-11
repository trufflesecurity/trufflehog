package github

import (
	"fmt"
	"strconv"
	"strings"
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
	apiClient          *github.Client
	graphqlClient      *githubv4.Client
	installationClient *github.Client
	installationID     int64
	appID              int64
	appPrivateKey      []byte
	apiEndpoint        string
	apiClientsMu       sync.Mutex
	// apiClientsByInstallationID is scoped to this connector/source run and is
	// bounded by the installations touched while scanning.
	apiClientsByInstallationID map[int64]*github.Client

	graphqlClientsMu               sync.Mutex
	graphqlClientsByInstallationID map[int64]*githubv4.Client

	// repoInstallationMap maps repo clone URLs to their owning installation
	// ID for repos discovered from non-default installations. Clone checks
	// this map to use the correct installation token.
	repoInstallationMu  sync.RWMutex
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

	connector := &appConnector{
		installationClient:             installationClient,
		installationID:                 installationID,
		appID:                          appID,
		appPrivateKey:                  []byte(app.PrivateKey),
		apiEndpoint:                    apiEndpoint,
		apiClientsByInstallationID:     make(map[int64]*github.Client),
		graphqlClientsByInstallationID: make(map[int64]*githubv4.Client),
		repoInstallationMap:            make(map[string]int64),
	}

	apiClient, err := connector.APIClientForInstallation(installationID)
	if err != nil {
		return nil, fmt.Errorf("could not create API client for configured installation: %w", err)
	}
	connector.apiClient = apiClient

	graphqlClient, err := createGraphqlClient(ctx, apiClient.Client(), apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("error creating GraphQL client: %w", err)
	}
	connector.graphqlClient = graphqlClient

	return connector, nil
}

func (c *appConnector) APIClient() *github.Client {
	return c.apiClient
}

func (c *appConnector) APIClientForRepo(repoURL string) (*github.Client, error) {
	installID := c.installationIDForRepo(repoURL)
	if installID == c.installationID {
		return c.apiClient, nil
	}
	return c.APIClientForInstallation(installID)
}

func (c *appConnector) GraphQLClientForRepo(ctx context.Context, repoURL string) (*githubv4.Client, error) {
	installID := c.installationIDForRepo(repoURL)
	if installID == c.installationID {
		return c.graphqlClient, nil
	}

	c.graphqlClientsMu.Lock()
	client, ok := c.graphqlClientsByInstallationID[installID]
	c.graphqlClientsMu.Unlock()
	if ok {
		return client, nil
	}

	// Create the client outside the lock to avoid nesting graphqlClientsMu
	// with apiClientsMu (taken by APIClientForInstallation).
	apiClient, err := c.APIClientForInstallation(installID)
	if err != nil {
		return nil, err
	}

	client, err = createGraphqlClient(ctx, apiClient.Client(), c.apiEndpoint)
	if err != nil {
		return nil, err
	}

	c.graphqlClientsMu.Lock()
	defer c.graphqlClientsMu.Unlock()
	if existing, ok := c.graphqlClientsByInstallationID[installID]; ok {
		return existing, nil
	}
	if c.graphqlClientsByInstallationID == nil {
		c.graphqlClientsByInstallationID = make(map[int64]*githubv4.Client)
	}
	c.graphqlClientsByInstallationID[installID] = client
	return client, nil
}

func (c *appConnector) Clone(ctx context.Context, repoURL string, args ...string) (string, *gogit.Repository, error) {
	installID := c.installationIDForRepo(repoURL)

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

func (c *appConnector) installationIDForRepo(repoURL string) int64 {
	c.repoInstallationMu.RLock()
	defer c.repoInstallationMu.RUnlock()

	if id, ok := c.repoInstallationMap[repoURL]; ok {
		return id
	}
	return c.installationID
}

func (c *appConnector) hasRepoInstallation(repoURL string) bool {
	c.repoInstallationMu.RLock()
	defer c.repoInstallationMu.RUnlock()

	_, ok := c.repoInstallationMap[repoURL]
	return ok
}

// setRepoInstallation records which installation owns a repo and its derived
// wiki URL so Clone uses the correct installation token for cross-org repos.
func (c *appConnector) setRepoInstallation(repoURL string, installationID int64) {
	c.repoInstallationMu.Lock()
	defer c.repoInstallationMu.Unlock()

	if c.repoInstallationMap == nil {
		c.repoInstallationMap = make(map[string]int64)
	}
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
	c.apiClientsMu.Lock()
	defer c.apiClientsMu.Unlock()

	if installationID == c.installationID && c.apiClient != nil {
		return c.apiClient, nil
	}
	if c.apiClientsByInstallationID == nil {
		c.apiClientsByInstallationID = make(map[int64]*github.Client)
	}
	if client, ok := c.apiClientsByInstallationID[installationID]; ok {
		return client, nil
	}

	appsTransportHTTPClient := common.RetryableHTTPClientTimeout(60)
	appsTransport, err := ghinstallation.NewAppsTransport(appsTransportHTTPClient.Transport, c.appID, c.appPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("could not create app transport for installation %d: %w", installationID, err)
	}
	appsTransport.BaseURL = c.apiEndpoint

	transport := ghinstallation.NewFromAppsTransport(appsTransport, installationID)
	transport.BaseURL = c.apiEndpoint

	httpClient := common.RetryableHTTPClientTimeout(60)
	httpClient.Transport = transport

	client, err := github.NewClient(httpClient).WithEnterpriseURLs(c.apiEndpoint, c.apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("could not create API client for installation %d: %w", installationID, err)
	}
	c.apiClientsByInstallationID[installationID] = client
	if installationID == c.installationID {
		c.apiClient = client
	}
	return client, nil
}
