package github

import (
	"fmt"
	"strconv"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v42/github"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

func (s *Source) cloneRepo(
	ctx context.Context,
	repoURL string,
	installationClient *github.Client,
) (string, *gogit.Repository, error) {
	var (
		path string
		repo *gogit.Repository
		err  error
	)

	switch s.conn.GetCredential().(type) {
	case *sourcespb.GitHub_BasicAuth:
		path, repo, err = git.CloneRepoUsingToken(ctx, s.conn.GetBasicAuth().GetPassword(), repoURL, s.conn.GetBasicAuth().GetUsername())
		if err != nil {
			return "", nil, fmt.Errorf("error cloning repo %s: %w", repoURL, err)
		}
	case *sourcespb.GitHub_Unauthenticated:
		path, repo, err = git.CloneRepoUsingUnauthenticated(ctx, repoURL)
		if err != nil {
			return "", nil, fmt.Errorf("error cloning repo %s: %w", repoURL, err)
		}

	case *sourcespb.GitHub_GithubApp:
		s.githubUser, s.githubToken, err = s.userAndToken(ctx, installationClient)
		if err != nil {
			return "", nil, fmt.Errorf("error getting token for repo %s: %w", repoURL, err)
		}

		path, repo, err = git.CloneRepoUsingToken(ctx, s.githubToken, repoURL, s.githubUser)
		if err != nil {
			return "", nil, fmt.Errorf("error cloning repo %s: %w", repoURL, err)
		}

	case *sourcespb.GitHub_Token:
		if err := s.getUserAndToken(ctx, repoURL, installationClient); err != nil {
			return "", nil, fmt.Errorf("error getting token for repo %s: %w", repoURL, err)
		}
		path, repo, err = git.CloneRepoUsingToken(ctx, s.githubToken, repoURL, s.githubUser)
		if err != nil {
			return "", nil, fmt.Errorf("error cloning repo %s: %w", repoURL, err)
		}
	default:
		return "", nil, fmt.Errorf("unhandled credential type for repo %s", repoURL)
	}
	return path, repo, nil
}

func (s *Source) getUserAndToken(ctx context.Context, repoURL string, installationClient *github.Client) error {
	// We never refresh user provided tokens, so if we already have them, we never need to try and fetch them again.
	s.userMu.Lock()
	defer s.userMu.Unlock()
	if s.githubUser == "" || s.githubToken == "" {
		var err error
		s.githubUser, s.githubToken, err = s.userAndToken(ctx, installationClient)
		if err != nil {
			return fmt.Errorf("error getting token for repo %s: %w", repoURL, err)
		}
	}
	return nil
}

func (s *Source) userAndToken(ctx context.Context, installationClient *github.Client) (string, string, error) {
	switch cred := s.conn.GetCredential().(type) {
	case *sourcespb.GitHub_BasicAuth:
		return cred.BasicAuth.Username, cred.BasicAuth.Password, nil
	case *sourcespb.GitHub_Unauthenticated:
		// do nothing
	case *sourcespb.GitHub_GithubApp:
		id, err := strconv.ParseInt(cred.GithubApp.InstallationId, 10, 64)
		if err != nil {
			return "", "", fmt.Errorf("unable to parse installation id: %w", err)
		}
		// TODO: Check rate limit for this call.
		token, _, err := installationClient.Apps.CreateInstallationToken(
			ctx, id, &github.InstallationTokenOptions{})
		if err != nil {
			return "", "", fmt.Errorf("unable to create installation token: %w", err)
		}
		return "x-access-token", token.GetToken(), nil // TODO: multiple workers request this, track the TTL
	case *sourcespb.GitHub_Token:
		var (
			ghUser *github.User
			resp   *github.Response
			err    error
		)
		for {
			ghUser, resp, err = s.apiClient.Users.Get(ctx, "")
			if handled := s.handleRateLimit(err, resp); handled {
				continue
			}
			if err != nil {
				return "", "", fmt.Errorf("unable to get user: %w", err)
			}
			break
		}
		return ghUser.GetLogin(), cred.Token, nil
	default:
		return "", "", fmt.Errorf("unhandled credential type")
	}

	return "", "", fmt.Errorf("unhandled credential type")
}

type repoListOptions interface {
	getListOptions() *github.ListOptions
}

type repoLister func(ctx context.Context, target string, opts repoListOptions) ([]*github.Repository, *github.Response, error)

type appListOptions struct {
	github.ListOptions
}

func (a *appListOptions) getListOptions() *github.ListOptions {
	return &a.ListOptions
}

func (s *Source) getReposByApp(ctx context.Context) error {
	return s.processRepos(ctx, "", s.appListReposWrapper, &appListOptions{
		ListOptions: github.ListOptions{
			PerPage: defaultPagination,
		},
	})
}

func (s *Source) appListReposWrapper(ctx context.Context, _ string, opts repoListOptions) ([]*github.Repository, *github.Response, error) {
	someRepos, res, err := s.apiClient.Apps.ListRepos(ctx, opts.getListOptions())
	if someRepos != nil {
		return someRepos.Repositories, res, err
	}
	return nil, res, err
}

type userListOptions struct {
	github.RepositoryListOptions
}

func (u *userListOptions) getListOptions() *github.ListOptions {
	return &u.ListOptions
}

func (s *Source) getReposByUser(ctx context.Context, user string) error {
	return s.processRepos(ctx, user, s.userListReposWrapper, &userListOptions{
		RepositoryListOptions: github.RepositoryListOptions{
			ListOptions: github.ListOptions{
				PerPage: defaultPagination,
			},
		},
	})
}

func (s *Source) userListReposWrapper(ctx context.Context, user string, opts repoListOptions) ([]*github.Repository, *github.Response, error) {
	return s.apiClient.Repositories.List(ctx, user, &opts.(*userListOptions).RepositoryListOptions)
}

type orgListOptions struct {
	github.RepositoryListByOrgOptions
}

func (o *orgListOptions) getListOptions() *github.ListOptions {
	return &o.ListOptions
}

func (s *Source) getReposByOrg(ctx context.Context, org string) error {
	return s.processRepos(ctx, org, s.orgListReposWrapper, &orgListOptions{
		RepositoryListByOrgOptions: github.RepositoryListByOrgOptions{
			ListOptions: github.ListOptions{
				PerPage: defaultPagination,
			},
		},
	})
}

func (s *Source) orgListReposWrapper(ctx context.Context, org string, opts repoListOptions) ([]*github.Repository, *github.Response, error) {
	return s.apiClient.Repositories.ListByOrg(ctx, org, &opts.(*orgListOptions).RepositoryListByOrgOptions)
}

func (s *Source) processRepos(ctx context.Context, target string, listRepos repoLister, listOpts repoListOptions) error {
	logger := s.log.WithValues("target", target)
	opts := listOpts.getListOptions()

	var (
		numRepos, numForks int
	)

	for {
		someRepos, res, err := listRepos(ctx, target, listOpts)
		if err == nil {
			res.Body.Close()
		}
		if handled := s.handleRateLimit(err, res); handled {
			continue
		}
		if err != nil {
			return err
		}
		if res == nil {
			break
		}

		s.log.V(2).Info("Listed repos", "page", opts.Page, "last_page", res.LastPage)
		for _, r := range someRepos {
			if r.GetFork() && !s.conn.IncludeForks {
				continue
			}
			numForks++

			repoName, repoURL := r.GetFullName(), r.GetCloneURL()
			s.repoSizes.addRepo(repoURL, r.GetSize())
			s.totalRepoSize += r.GetSize()
			s.filteredRepoCache.Set(repoName, repoURL)
			logger.V(3).Info("repo attributes", "name", repoName, "size", r.GetSize(), "repo_url", repoURL)
		}

		if res.NextPage == 0 {
			break
		}
		opts.Page = res.NextPage
	}
	logger.V(2).Info("found repos", "total", numRepos, "num_forks", numForks)

	return nil
}

func (s *Source) normalizeRepo(repo string) (string, error) {
	// If there's a '/', assume it's a URL and try to normalize it.
	if strings.ContainsRune(repo, '/') {
		return giturl.NormalizeGithubRepo(repo)
	}

	return "", fmt.Errorf("no repositories found for %s", repo)
}
