package github

// This "registry" serves as a cache of github app clients across the whole
// process, so we work with single instances of clients that don't need to
// fetch access tokens separately and can better track rate limits.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v67/github"
	"github.com/maypok86/otter/v2"
	"github.com/shurcooL/githubv4"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	trContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var (
	appClients              *otter.Cache[appClientKey, *github.Client]
	clientsByInstallationID *otter.Cache[appInstallationClientKey, *AppInstallationClients]
)

var initCaches = sync.OnceFunc(func() {
	appClients = otter.Must(&otter.Options[appClientKey, *github.Client]{})

	clientsByInstallationID = otter.Must(&otter.Options[appInstallationClientKey, *AppInstallationClients]{
		MaximumSize: 1000,
	})
})

type appClientKey struct {
	apiEndpoint string
	appID       int64
	privateKey  string
}

type appInstallationClientKey struct {
	appClientKey
	installationID int64
}

type AppInstallationClients struct {
	appClient      *github.Client
	InstallationID int64
	APIClient      *github.Client
	GraphQLClient  *githubv4.Client
	tokenMu        sync.RWMutex
	token          *github.InstallationToken
}

// AccessToken returns an installation access token.  If not present yet or
// expired, one is fetched.  The expiry is adjusted so we refresh one minute
// early.
func (cs *AppInstallationClients) AccessToken(ctx context.Context) (string, error) {
	if cs.InstallationID == 0 {
		return "", fmt.Errorf("tried to fetch installation access token for id 0")
	}

	cs.tokenMu.RLock()
	token := cs.accessTokenIfValid()
	cs.tokenMu.RUnlock()

	if token != nil {
		return token.GetToken(), nil
	}

	cs.tokenMu.Lock()
	defer cs.tokenMu.Unlock()

	if token := cs.accessTokenIfValid(); token != nil {
		return token.GetToken(), nil
	}

	token, _, err := cs.appClient.Apps.CreateInstallationToken(
		ctx, cs.InstallationID, &github.InstallationTokenOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("could not create installation token for installation %d: %w", cs.InstallationID, err)
	}

	if exp := token.GetExpiresAt(); !exp.IsZero() {
		// Refresh just before the real expiry
		token.ExpiresAt = &github.Timestamp{Time: exp.Add(-time.Minute)}
	}

	cs.token = token

	return token.GetToken(), nil
}

// GrantedPermissions returns the permissions the installation grants, as
// listed on its access token. GitHub sends them with every token it issues,
// so this costs no API call when a token is already cached, which is the
// usual case: a repo is cloned with the same token before its comments are
// scanned. The comment scan reads them to skip, or report as incomplete,
// listings the installation can't fully cover (see installationGrants).
func (cs *AppInstallationClients) GrantedPermissions(ctx context.Context) (*github.InstallationPermissions, error) {
	if _, err := cs.AccessToken(ctx); err != nil {
		return nil, err
	}

	cs.tokenMu.RLock()
	defer cs.tokenMu.RUnlock()
	return cs.token.GetPermissions(), nil
}

func (cs *AppInstallationClients) accessTokenIfValid() *github.InstallationToken {
	if cs.token == nil || cs.token.GetExpiresAt().Before(time.Now()) {
		return nil
	}
	return cs.token
}

// GetAppClient creates or returns from cache a github API client for the given
// app.  This is the client that isn't associated with a specific installation.
func GetAppClient(ctx context.Context, apiEndpoint string, appID int64, privateKey string) (*github.Client, error) {
	initCaches()

	loader := func(ctx context.Context, key appClientKey) (*github.Client, error) {
		transport, err := newAppsTransport(key.apiEndpoint, key.appID, []byte(key.privateKey))
		if err != nil {
			return nil, fmt.Errorf("could not create app client transport: %w", err)
		}

		client, err := newGitHubClientWithTransport(key.apiEndpoint, transport)
		if err != nil {
			return nil, fmt.Errorf("could not create app client: %w", err)
		}

		return client, nil
	}

	return appClients.Get(
		ctx,
		appClientKey{apiEndpoint, appID, privateKey},
		otter.LoaderFunc[appClientKey, *github.Client](loader),
	)
}

// GetAppInstallationClients returns a struct holding API and GraphQL clients
// for the requested app and installation, from cache if available.
func GetAppInstallationClients(
	ctx context.Context,
	apiEndpoint string,
	appID int64,
	privateKey string,
	instID int64,
) (*AppInstallationClients, error) {
	initCaches()

	loader := func(ctx context.Context, key appInstallationClientKey) (*AppInstallationClients, error) {
		ac, err := GetAppClient(ctx, key.apiEndpoint, key.appID, key.privateKey)
		if err != nil {
			return nil, err
		}

		appsTransport, err := newAppsTransport(key.apiEndpoint, key.appID, []byte(key.privateKey))
		if err != nil {
			return nil, fmt.Errorf("could not create app transport for installation %d: %w", instID, err)
		}

		// NewFromAppsTransport inherits BaseURL from appsTransport, which
		// newAppsTransport already set correctly (incl. GHE.com). Don't override it
		// with the raw endpoint here or GHE.com token refresh would 401.
		transport := ghinstallation.NewFromAppsTransport(appsTransport, instID)

		apiClient, err := newGitHubClientWithTransport(key.apiEndpoint, transport)
		if err != nil {
			return nil, fmt.Errorf("could not create API client for installation %d: %w", instID, err)
		}

		gqlClient, err := createGraphqlClient(trContext.AddLogger(ctx), apiClient.Client(), key.apiEndpoint)
		if err != nil {
			return nil, err
		}

		return &AppInstallationClients{
			appClient:      ac,
			InstallationID: instID,
			APIClient:      apiClient,
			GraphQLClient:  gqlClient,
		}, nil
	}

	return clientsByInstallationID.Get(
		ctx,
		appInstallationClientKey{appClientKey{apiEndpoint, appID, privateKey}, instID},
		otter.LoaderFunc[appInstallationClientKey, *AppInstallationClients](loader),
	)
}

func newAppsTransport(apiEndpoint string, appID int64, privateKey []byte) (*ghinstallation.AppsTransport, error) {
	httpClient := common.RetryableHTTPClientTimeout(githubHTTPTimeoutSeconds)
	appsTransport, err := ghinstallation.NewAppsTransport(httpClient.Transport, appID, privateKey)
	if err != nil {
		return nil, err
	}

	// ghinstallation uses BaseURL to build the token exchange URL
	// {BaseURL}/app/installations/{id}/access_tokens. For GHE.com this must be
	// the api.SUBDOMAIN.ghe.com base with no /api/v3 and no trailing slash
	// (which ghinstallation does not expect), otherwise token refresh 401s.
	baseURL, err := appsBaseURL(apiEndpoint)
	if err != nil {
		return nil, err
	}
	appsTransport.BaseURL = strings.TrimRight(baseURL, "/")
	return appsTransport, nil
}

// appsBaseURL returns the BaseURL that ghinstallation transports should use
// for token exchange/refresh. For GHE.com it resolves to the api.* subdomain;
// for what is likely GHES, it ensures /api/v3 is used; and for anything else
// including github.com it is the endpoint as-is.
func appsBaseURL(apiEndpoint string) (string, error) {
	if isGHECloud(apiEndpoint) {
		normalizedURL, err := normalizeGHECloudAPIEndpoint(apiEndpoint)
		if err != nil {
			return "", fmt.Errorf("could not normalize GHE.com endpoint: %w", err)
		}
		return normalizedURL, nil
	}

	u, err := url.Parse(apiEndpoint)
	if err != nil {
		return "", fmt.Errorf("malformed endpoint url: %w", err)
	}
	h := u.Hostname()

	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}

	// If we're not dealing with github.com or GHE, then maybe GHES, which
	// needs /api/v3 for ghinstallation find the right place
	if !strings.HasPrefix(h, "api.") && !strings.Contains(h, ".api.") {
		if !strings.HasSuffix(u.Path, "/api/v3/") {
			u.Path += "api/v3/"
		}
	}

	return u.String(), nil
}

func newGitHubClientWithTransport(apiEndpoint string, transport http.RoundTripper) (*github.Client, error) {
	httpClient := common.RetryableHTTPClientTimeout(githubHTTPTimeoutSeconds)
	httpClient.Transport = transport

	// GHE.com (GHEC with data residency) serves its REST API at the root of
	// api.SUBDOMAIN.ghe.com (like api.github.com), NOT under the GHES /api/v3 path.
	if isGHECloud(apiEndpoint) {
		return createGHECloudClient(httpClient, apiEndpoint)
	}
	return github.NewClient(httpClient).WithEnterpriseURLs(apiEndpoint, apiEndpoint)
}
