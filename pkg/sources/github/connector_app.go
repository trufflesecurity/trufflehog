package github

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v63/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type appConnector struct {
	httpClient         *http.Client
	apiClient          *github.Client
	installationClient *github.Client
	installationID     int64
	isGitHubEnterprise bool
}

var _ connector = (*appConnector)(nil)

func newAppConnector(apiEndpoint string, app *credentialspb.GitHubApp) (*appConnector, error) {
	installationID, err := strconv.ParseInt(app.InstallationId, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("could not parse app installation ID %q: %w", app.InstallationId, err)
	}

	appID, err := strconv.ParseInt(app.AppId, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("could not parse app ID %q: %w", appID, err)
	}

	httpClient := common.RetryableHTTPClientTimeout(60)

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

	return &appConnector{
		httpClient:         httpClient,
		apiClient:          apiClient,
		installationClient: installationClient,
		installationID:     installationID,
		isGitHubEnterprise: !strings.EqualFold(apiEndpoint, cloudEndpoint),
	}, nil
}

func (c *appConnector) ApiClient() *github.Client {
	return c.apiClient
}

func (c *appConnector) Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error) {
	// TODO: Check rate limit for this call.
	token, _, err := c.installationClient.Apps.CreateInstallationToken(
		ctx,
		c.installationID,
		&github.InstallationTokenOptions{})
	if err != nil {
		return "", nil, fmt.Errorf("could not create installation token: %w", err)
	}

	return git.CloneRepoUsingToken(ctx, token.GetToken(), repoURL, "x-access-token")
}

func (c *appConnector) IsGithubEnterprise() bool {
	return c.isGitHubEnterprise
}

func (c *appConnector) HttpClient() *http.Client {
	return c.httpClient
}

func (c *appConnector) InstallationClient() *github.Client {
	return c.installationClient
}
