package github

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v63/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
	"golang.org/x/oauth2"
)

type tokenConnector struct {
	httpClient         *http.Client
	apiClient          *github.Client
	token              string
	isGitHubEnterprise bool
	handleRateLimit    func(error) bool
	user               string
	userMu             sync.Mutex
}

var _ connector = (*tokenConnector)(nil)

func newTokenConnector(apiEndpoint string, token string, handleRateLimit func(error) bool) (*tokenConnector, error) {
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	httpClient := common.RetryableHTTPClientTimeout(60)
	httpClient.Transport = &oauth2.Transport{
		Base:   httpClient.Transport,
		Source: oauth2.ReuseTokenSource(nil, tokenSource),
	}

	apiClient, err := createGitHubClient(httpClient, apiEndpoint)
	if err != nil {
		return nil, err
	}

	return &tokenConnector{
		httpClient:         httpClient,
		apiClient:          apiClient,
		token:              token,
		isGitHubEnterprise: !strings.EqualFold(apiEndpoint, cloudEndpoint),
		handleRateLimit:    handleRateLimit,
	}, nil
}

func (c *tokenConnector) ApiClient() *github.Client {
	return c.apiClient
}

func (c *tokenConnector) Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error) {
	if err := c.setUserIfUnset(ctx); err != nil {
		return "", nil, err
	}
	return git.CloneRepoUsingToken(ctx, c.token, repoURL, c.user)
}

func (c *tokenConnector) IsGithubEnterprise() bool {
	return c.isGitHubEnterprise
}

func (c *tokenConnector) HttpClient() *http.Client {
	return c.httpClient
}

func (c *tokenConnector) InstallationClient() *github.Client {
	return nil
}

func (c *tokenConnector) getUser(ctx context.Context) (string, error) {
	var (
		user *github.User
		err  error
	)
	for {
		user, _, err = c.apiClient.Users.Get(ctx, "")
		if c.handleRateLimit(err) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("could not get GitHub user: %w", err)
		}
		break
	}
	return user.GetLogin(), nil
}

func (c *tokenConnector) setUserIfUnset(ctx context.Context) error {
	c.userMu.Lock()
	defer c.userMu.Unlock()

	if c.user == "" {
		if user, err := c.getUser(ctx); err != nil {
			return err
		} else {
			c.user = user
		}
	}

	return nil
}
