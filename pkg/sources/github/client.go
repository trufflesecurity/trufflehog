package github

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v62/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"golang.org/x/oauth2"
)

type client struct {
	github.Client
}

func createGitHubClient(httpClient *http.Client, apiEndpoint string) (*github.Client, error) {
	// If we're using public GitHub, make a regular client.
	// Otherwise, make an enterprise client.
	if strings.EqualFold(apiEndpoint, cloudEndpoint) {
		return github.NewClient(httpClient), nil
	}

	return github.NewClient(httpClient).WithEnterpriseURLs(apiEndpoint, apiEndpoint)
}

func newAppClient(app *credentialspb.GitHubApp, apiEndpoint string) (*github.Client, *github.Client, error) {
	installationID, err := strconv.ParseInt(app.InstallationId, 10, 64)
	if err != nil {
		return nil, nil, err
	}

	appID, err := strconv.ParseInt(app.AppId, 10, 64)
	if err != nil {
		return nil, nil, err
	}

	httpClient := common.RetryableHTTPClientTimeout(60)
	installationTransport, err := ghinstallation.NewAppsTransport(
		httpClient.Transport,
		appID,
		[]byte(app.PrivateKey))
	if err != nil {
		return nil, nil, err
	}
	installationTransport.BaseURL = apiEndpoint
	installationHttpClient := common.RetryableHTTPClientTimeout(60)
	installationHttpClient.Transport = installationTransport
	installationClient, err := github.NewClient(installationHttpClient).WithEnterpriseURLs(apiEndpoint, apiEndpoint)
	if err != nil {
		return nil, nil, err
	}

	apiTransport, err := ghinstallation.New(
		httpClient.Transport,
		appID,
		installationID,
		[]byte(app.PrivateKey))
	if err != nil {
		return nil, nil, err
	}
	apiTransport.BaseURL = apiEndpoint
	httpClient.Transport = apiTransport
	apiClient, err := github.NewClient(httpClient).WithEnterpriseURLs(apiEndpoint, apiEndpoint)
	if err != nil {
		return nil, nil, err
	}

	return apiClient, installationClient, nil
}

func newBasicAuthClient(basicAuth *credentialspb.BasicAuth, apiEndpoint string) (*github.Client, error) {
	httpClient := common.RetryableHTTPClientTimeout(60)
	httpClient.Transport = &github.BasicAuthTransport{
		Username: basicAuth.Username,
		Password: basicAuth.Password,
	}
	return createGitHubClient(httpClient, apiEndpoint)
}

func newTokenClient(token, apiEndpoint string) (*github.Client, error) {
	httpClient := common.RetryableHTTPClientTimeout(60)
	httpClient.Transport = &oauth2.Transport{
		Base:   httpClient.Transport,
		Source: oauth2.ReuseTokenSource(nil, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})),
	}
	return createGitHubClient(httpClient, apiEndpoint)
}

func newUnauthenticatedClient(apiEndpoint string) (*github.Client, error) {
	return createGitHubClient(common.RetryableHTTPClientTimeout(60), apiEndpoint)
}
