package github

import (
	"net/http"
	"strings"

	"github.com/google/go-github/v62/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
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

func newBasicAuthClient(basicAuth *credentialspb.BasicAuth, apiEndpoint string) (*github.Client, error) {
	httpClient := common.RetryableHTTPClientTimeout(60)
	httpClient.Transport = &github.BasicAuthTransport{
		Username: basicAuth.Username,
		Password: basicAuth.Password,
	}
	return createGitHubClient(httpClient, apiEndpoint)
}

func newUnauthenticatedClient(apiEndpoint string) (*github.Client, error) {
	return createGitHubClient(common.RetryableHTTPClientTimeout(60), apiEndpoint)
}
