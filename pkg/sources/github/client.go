package github

import (
	"net/http"
	"strconv"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v62/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"golang.org/x/oauth2"
)

type clients struct {
	httpClient         *http.Client
	apiClient          *github.Client
	installationClient *github.Client
	githubToken        string
}

func newAppClients(apiEndpoint string, app *credentialspb.GitHubApp) (clients, error) {
	installationID, err := strconv.ParseInt(app.InstallationId, 10, 64)
	if err != nil {
		return clients{}, err
	}

	appID, err := strconv.ParseInt(app.AppId, 10, 64)
	if err != nil {
		return clients{}, err
	}

	httpClient := common.RetryableHTTPClientTimeout(60)

	installationTransport, err := ghinstallation.NewAppsTransport(
		httpClient.Transport,
		appID,
		[]byte(app.PrivateKey))
	if err != nil {
		return clients{}, nil
	}
	installationTransport.BaseURL = apiEndpoint
	installationHttpClient := common.RetryableHTTPClientTimeout(60)
	installationHttpClient.Transport = installationTransport
	installationClient, err := github.NewClient(installationHttpClient).WithEnterpriseURLs(apiEndpoint, apiEndpoint)
	if err != nil {
		return clients{}, nil
	}

	apiTransport, err := ghinstallation.New(
		httpClient.Transport,
		appID,
		installationID,
		[]byte(app.PrivateKey))
	if err != nil {
		return clients{}, err
	}
	apiTransport.BaseURL = apiEndpoint
	httpClient.Transport = apiTransport
	apiClient, err := github.NewClient(httpClient).WithEnterpriseURLs(apiEndpoint, apiEndpoint)
	if err != nil {
		return clients{}, err
	}

	return clients{
		httpClient:         httpClient,
		apiClient:          apiClient,
		installationClient: installationClient,
	}, nil
}

func newBasicAuthClients(apiEndpoint string, basicAuth *github.BasicAuthTransport) (clients, error) {
	httpClient := common.RetryableHTTPClientTimeout(60)
	httpClient.Transport = &github.BasicAuthTransport{
		Username: basicAuth.Username,
		Password: basicAuth.Password,
	}
	apiClient, err := createGitHubClient(httpClient, apiEndpoint)
	if err != nil {
		return clients{}, err
	}
	return clients{
		httpClient: httpClient,
		apiClient:  apiClient,
	}, nil
}

func newTokenClients(apiEndpoint, token string) (clients, error) {
	httpClient := common.RetryableHTTPClientTimeout(60)
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	httpClient.Transport = &oauth2.Transport{
		Base:   httpClient.Transport,
		Source: oauth2.ReuseTokenSource(nil, ts),
	}
	apiClient, err := createGitHubClient(httpClient, apiEndpoint)
	if err != nil {
		return clients{}, err
	}
	return clients{
		httpClient:  httpClient,
		apiClient:   apiClient,
		githubToken: token,
	}, nil
}

func newUnauthenticatedClients(apiEndpoint string) (clients, error) {
	httpClient := common.RetryableHTTPClientTimeout(60)
	apiClient, err := createGitHubClient(httpClient, apiEndpoint)
	if err != nil {
		return clients{}, err
	}
	return clients{
		httpClient: httpClient,
		apiClient:  apiClient,
	}, nil
}
