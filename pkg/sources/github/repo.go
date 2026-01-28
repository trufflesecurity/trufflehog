package github

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v67/github"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// repoInfoCache is a thread-safe cache to store information about repositories.
type repoInfoCache struct {
	mu    sync.RWMutex
	cache map[string]repoInfo // the actual cache storing the repository information by URL.
}

// newRepoInfoCache creates a new instance of repoInfoCache with an empty cache.
func newRepoInfoCache() repoInfoCache {
	return repoInfoCache{
		cache: make(map[string]repoInfo),
	}
}

// put adds repository information to the cache, locking for thread safety.
func (r *repoInfoCache) put(repoURL string, info repoInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[repoURL] = info
}

// get retrieves repository information from the cache, locking for thread safety.
// it returns the info and a boolean indicating whether it was found.
func (r *repoInfoCache) get(repoURL string) (repoInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, ok := r.cache[repoURL]
	return info, ok
}

// repoInfo holds basic metadata about a repository.
type repoInfo struct {
	owner      string                       // repository owner (user|organization).
	name       string                       // repository name.
	fullName   string                       // full repository name (owner/repo).
	hasWiki    bool                         // whether the repository is likely to have a wiki.
	size       int                          // size of the repository in kilobytes.
	visibility source_metadatapb.Visibility // visibility of the repository (public/private).
}

// cloneRepo clones a repository given its URL, returns the path and the repository object.
func (s *Source) cloneRepo(ctx context.Context, repoURL string) (string, *gogit.Repository, error) {
	return s.connector.Clone(ctx, repoURL)
}

// repoListOptions is an interface for types that provide options for listing repositories.
type repoListOptions interface {
	getListOptions() *github.ListOptions
}

// repoLister is a function signature for listing repositories based on certain options.
type repoLister func(ctx context.Context, target string, opts repoListOptions) ([]*github.Repository, *github.Response, error)

// === GitHub App Repositories ===

// appListOptions represents options for listing repositories by GitHub Apps.
type appListOptions struct {
	github.ListOptions
}

// getListOptions returns the ListOptions for appListOptions.
func (a *appListOptions) getListOptions() *github.ListOptions {
	return &a.ListOptions
}

// appListReposWrapper lists repositories for a GitHub App, using the provided options.
func (s *Source) appListReposWrapper(ctx context.Context, _ string, opts repoListOptions) ([]*github.Repository, *github.Response, error) {
	someRepos, res, err := s.connector.APIClient().Apps.ListRepos(ctx, opts.getListOptions())
	if someRepos != nil {
		return someRepos.Repositories, res, err
	}
	return nil, res, err
}

// getReposByApp retrieves repositories by a GitHub App.
func (s *Source) getReposByApp(ctx context.Context, reporter sources.UnitReporter) error {
	return s.processRepos(ctx, "", reporter, s.appListReposWrapper, &appListOptions{
		ListOptions: github.ListOptions{
			PerPage: defaultPagination, // Default pagination setting for API requests.
		},
	})
}

// === GitHub User Repositories ===

// userListOptions represents options for listing repositories by user.
type userListOptions struct {
	github.RepositoryListByUserOptions // embedded options for listing repositories by user.
}

// getListOptions returns the ListOptions for userListOptions.
func (u *userListOptions) getListOptions() *github.ListOptions {
	return &u.ListOptions
}

// authenticatedUserListOption represents options for listing repositories by authenticated user.
type authenticatedUserListOption struct {
	github.RepositoryListByAuthenticatedUserOptions // embedded options for listing repositories by authenticated user.
}

// getListOptions returns the ListOptions for authenticatedUserListOption.
func (a *authenticatedUserListOption) getListOptions() *github.ListOptions {
	return &a.ListOptions
}

// userListReposWrapper lists repositories for a user, using the provided options.
func (s *Source) userListReposWrapper(ctx context.Context, user string, opts repoListOptions) ([]*github.Repository, *github.Response, error) {
	return s.connector.APIClient().Repositories.ListByUser(ctx, user, &opts.(*userListOptions).RepositoryListByUserOptions)
}

// authenticatedUserListReposWrapper lists repositories for an authenticated user, using the provided options.
func (s *Source) authenticatedUserListReposWrapper(ctx context.Context, user string, opts repoListOptions) ([]*github.Repository, *github.Response, error) {
	return s.connector.APIClient().Repositories.ListByAuthenticatedUser(ctx, &opts.(*authenticatedUserListOption).RepositoryListByAuthenticatedUserOptions)
}

// getReposByUser retrieves repositories for a given user.
func (s *Source) getReposByUser(ctx context.Context, user string, authenticated bool, reporter sources.UnitReporter) error {
	if authenticated {
		return s.processRepos(ctx, user, reporter, s.authenticatedUserListReposWrapper, &authenticatedUserListOption{
			RepositoryListByAuthenticatedUserOptions: github.RepositoryListByAuthenticatedUserOptions{
				ListOptions: github.ListOptions{
					PerPage: defaultPagination,
				},
			},
		})
	}

	return s.processRepos(ctx, user, reporter, s.userListReposWrapper, &userListOptions{
		RepositoryListByUserOptions: github.RepositoryListByUserOptions{
			ListOptions: github.ListOptions{
				PerPage: defaultPagination,
			},
		},
	})
}

// === GitHub Organization Repositories ===

// orgListOptions represents options for listing repositories by organization.
type orgListOptions struct {
	github.RepositoryListByOrgOptions // Embedded options for listing repositories by organization.
}

// getListOptions returns the ListOptions for orgListOptions.
func (o *orgListOptions) getListOptions() *github.ListOptions {
	return &o.ListOptions
}

// orgListReposWrapper lists repositories for an organization, using the provided options.
func (s *Source) orgListReposWrapper(ctx context.Context, org string, opts repoListOptions) ([]*github.Repository, *github.Response, error) {
	// TODO: It's possible to exclude forks when making the API request rather than doing post-request filtering.
	return s.connector.APIClient().Repositories.ListByOrg(ctx, org, &opts.(*orgListOptions).RepositoryListByOrgOptions)
}

// getReposByOrg retrieves repositories for a given organization.
func (s *Source) getReposByOrg(ctx context.Context, org string, reporter sources.UnitReporter) error {
	return s.processRepos(ctx, org, reporter, s.orgListReposWrapper, &orgListOptions{
		RepositoryListByOrgOptions: github.RepositoryListByOrgOptions{
			ListOptions: github.ListOptions{
				PerPage: defaultPagination,
			},
		},
	})
}

// userType indicates whether an account belongs to a person or organization.
//
// See:
// - https://docs.github.com/en/get-started/learning-about-github/types-of-github-accounts
// - https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-a-user
type userType int

// Constants for userType.
const (
	unknown      userType = iota // default invalid state.
	user                         // the account is a person (https://docs.github.com/en/rest/users/users).
	organization                 // the account is an organization (https://docs.github.com/en/rest/orgs/orgs).
)

// getReposByOrgOrUser retrieves repositories for an organization or user.
func (s *Source) getReposByOrgOrUser(ctx context.Context, name string, authenticated bool, reporter sources.UnitReporter) (userType, error) {
	var err error

	// try to get repositories for the organization first.
	err = s.getReposByOrg(ctx, name, reporter)
	if err == nil {
		return organization, nil
	} else if !isGitHub404Error(err) { // if the error is not a "not found" error, report it.
		if err := reporter.UnitErr(ctx, fmt.Errorf("error getting repos by org: %w", err)); err != nil {
			return unknown, err
		}

		return unknown, err
	}

	// if organization repos aren't found, try user repos.
	err = s.getReposByUser(ctx, name, authenticated, reporter)
	if err == nil {
		if err := s.addUserGistsToCache(ctx, name, reporter); err != nil {
			ctx.Logger().Error(err, "Unable to add user to cache")
		}
		return user, nil
	} else if !isGitHub404Error(err) { // if the error is not a "not found" error, report it.
		return unknown, err
	}

	// if neither organization nor user repos are found, return an error.
	return unknown, fmt.Errorf("account '%s' not found", name)
}

// isGitHub404Error checks if the error is a GitHub API error with a 404 status.
func isGitHub404Error(err error) bool {
	var ghErr *github.ErrorResponse
	if !errors.As(err, &ghErr) {
		return false
	}

	return ghErr.Response.StatusCode == http.StatusNotFound
}

// processRepos processes repositories from a source, handling pagination and rate limits.
func (s *Source) processRepos(ctx context.Context, target string, reporter sources.UnitReporter, listRepos repoLister, listOpts repoListOptions) error {
	logger := ctx.Logger().WithValues("target", target)
	opts := listOpts.getListOptions()

	var (
		numRepos, numForks int
		uniqueOrgs         = map[string]struct{}{}
	)

	// loop to handle pagination.
	for {
		someRepos, res, err := listRepos(ctx, target, listOpts)
		if s.handleRateLimitWithUnitReporter(ctx, reporter, err) {
			continue
		}
		if err != nil {
			return err
		}

		ctx.Logger().V(2).Info("Listed repos", "page", opts.Page, "last_page", res.LastPage)
		for _, r := range someRepos {
			if r.GetFork() {
				if !s.conn.IncludeForks {
					continue
				}
				numForks++
			}
			numRepos++

			// track unique organizations.
			if r.GetOwner().GetType() == "Organization" {
				uniqueOrgs[r.GetOwner().GetLogin()] = struct{}{}
			}

			repoName, repoURL := r.GetFullName(), r.GetCloneURL()

			// Check if we should process this repository based on the filter
			if !s.filteredRepoCache.wantRepo(repoName) {
				continue
			}

			s.totalRepoSize += r.GetSize()
			s.filteredRepoCache.Set(repoName, repoURL)
			s.cacheRepoInfo(r)
			if err := reporter.UnitOk(ctx, RepoUnit{Name: repoName, URL: repoURL}); err != nil {
				return err
			}

			logger.V(3).Info("repo attributes", "name", repoName, "kb_size", r.GetSize(), "repo_url", repoURL)
		}

		if res.NextPage == 0 {
			break
		}
		opts.Page = res.NextPage
	}

	// final logging of repository stats.
	logger.V(2).Info("found repos", "total", numRepos, "num_forks", numForks, "num_orgs", len(uniqueOrgs))
	githubOrgsEnumerated.WithLabelValues(s.name).Add(float64(len(uniqueOrgs)))

	return nil
}

// cacheRepoInfo caches basic information about a repository for later use.
func (s *Source) cacheRepoInfo(r *github.Repository) {
	info := repoInfo{
		owner:    r.GetOwner().GetLogin(),
		name:     r.GetName(),
		fullName: r.GetFullName(),
		hasWiki:  r.GetHasWiki(),
		size:     r.GetSize(),
	}
	if r.GetPrivate() {
		info.visibility = source_metadatapb.Visibility_private
	} else {
		info.visibility = source_metadatapb.Visibility_public
	}
	s.repoInfoCache.put(r.GetCloneURL(), info)
}

// cacheGistInfo caches information about a Gist.
func (s *Source) cacheGistInfo(g *github.Gist) {
	info := repoInfo{
		owner: g.GetOwner().GetLogin(),
	}
	if g.GetPublic() {
		info.visibility = source_metadatapb.Visibility_public
	} else {
		info.visibility = source_metadatapb.Visibility_private
	}
	s.repoInfoCache.put(g.GetGitPullURL(), info)
}

// wikiIsReachable checks if the wiki for a repository is reachable by sending a HEAD request.
// Unfortunately, this isn't 100% accurate. Some repositories have `has_wiki: true` and don't redirect their wiki page,
// but still don't have a cloneable wiki.
func (s *Source) wikiIsReachable(ctx context.Context, repoURL string) bool {
	wikiURL := strings.TrimSuffix(repoURL, ".git") + "/wiki"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, wikiURL, nil)
	if err != nil {
		return false
	}

	res, err := s.connector.APIClient().Client().Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	// if the wiki is disabled or unreachable, the request will be redirected.
	return wikiURL == res.Request.URL.String()
}

// normalizeRepo normalizes a GitHub repository URL or name to its canonical form.
func (s *Source) normalizeRepo(repo string) (string, error) {

	// If it's a full URL (has protocol), normalize it
	if regexp.MustCompile(`^[a-z]+://`).MatchString(repo) {

		return giturl.NormalizeGithubRepo(repo)
	}
	// If it's a repository name (contains / but not http), convert to full URL first
	if strings.Contains(repo, "/") && !regexp.MustCompile(`^[a-z]+://`).MatchString(repo) {
		fullURL := "https://github.com/" + repo
		// If using GitHub Enterprise, adjust the URL accordingly
		if s.conn != nil && s.conn.Endpoint != "" {
			u, err := url.Parse(s.conn.Endpoint)
			if err != nil {
				return "", fmt.Errorf("invalid enterprise endpoint: %w", err)
			}
			// we want to remove any path components from the endpoint and just use the host
			u.Path = "/" + repo
			fullURL = u.String()
		}
		return giturl.NormalizeGithubRepo(fullURL)
	}

	return "", fmt.Errorf("no repositories found for %s", repo)
}

// extractRepoNameFromUrl extracts the "owner/repo" name from a GitHub repository URL.
// Example: http://github.com/owner/repo.git -> owner/repo
// If an invalid URL is provided, it returns the original string.
func extractRepoNameFromUrl(repoURL string) string {
	u, err := url.Parse(repoURL)
	if err != nil {
		return repoURL
	}
	cleanedPath := strings.Trim(u.Path, "/")
	return strings.TrimSuffix(cleanedPath, ".git")
}
