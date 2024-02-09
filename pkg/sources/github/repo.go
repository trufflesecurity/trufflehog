package github

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v57/github"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type repoInfoCache struct {
	mu    sync.RWMutex
	cache map[string]repoInfo
}

func newRepoInfoCache() repoInfoCache {
	return repoInfoCache{
		cache: make(map[string]repoInfo),
	}
}

func (r *repoInfoCache) put(repoURL string, info repoInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[repoURL] = info
}

func (r *repoInfoCache) get(repoURL string) (repoInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, ok := r.cache[repoURL]
	return info, ok
}

type repoInfo struct {
	owner      string
	name       string
	fullName   string
	hasWiki    bool // the repo is _likely_ to have a wiki (see the comment on wikiIsReachable func).
	size       int
	visibility source_metadatapb.Visibility
}

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
			err    error
		)
		for {
			ghUser, _, err = s.apiClient.Users.Get(ctx, "")
			if s.handleRateLimit(err) {
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
	github.RepositoryListByUserOptions
}

func (u *userListOptions) getListOptions() *github.ListOptions {
	return &u.ListOptions
}

func (s *Source) getReposByUser(ctx context.Context, user string) error {
	return s.processRepos(ctx, user, s.userListReposWrapper, &userListOptions{
		RepositoryListByUserOptions: github.RepositoryListByUserOptions{
			ListOptions: github.ListOptions{
				PerPage: defaultPagination,
			},
		},
	})
}

func (s *Source) userListReposWrapper(ctx context.Context, user string, opts repoListOptions) ([]*github.Repository, *github.Response, error) {
	return s.apiClient.Repositories.ListByUser(ctx, user, &opts.(*userListOptions).RepositoryListByUserOptions)
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
		uniqueOrgs         = map[string]struct{}{}
	)

	for {
		someRepos, res, err := listRepos(ctx, target, listOpts)
		if s.handleRateLimit(err) {
			continue
		}
		if err != nil {
			return err
		}

		s.log.V(2).Info("Listed repos", "page", opts.Page, "last_page", res.LastPage)
		for _, r := range someRepos {
			if r.GetFork() {
				if !s.conn.IncludeForks {
					continue
				}
				numForks++
			}
			numRepos++

			if r.GetOwner().GetType() == "Organization" {
				uniqueOrgs[r.GetOwner().GetLogin()] = struct{}{}
			}

			repoName, repoURL := r.GetFullName(), r.GetCloneURL()
			s.totalRepoSize += r.GetSize()
			s.filteredRepoCache.Set(repoName, repoURL)

			s.cacheRepoInfo(r)
			logger.V(3).Info("repo attributes", "name", repoName, "kb_size", r.GetSize(), "repo_url", repoURL)
		}

		if res.NextPage == 0 {
			break
		}
		opts.Page = res.NextPage
	}

	logger.V(2).Info("found repos", "total", numRepos, "num_forks", numForks, "num_orgs", len(uniqueOrgs))
	githubOrgsEnumerated.WithLabelValues(s.name).Set(float64(len(uniqueOrgs)))

	return nil
}

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

// wikiIsReachable returns true if https://github.com/$org/$repo/wiki is not redirected.
// Unfortunately, this isn't 100% accurate. Some repositories have `has_wiki: true` and don't redirect their wiki page,
// but still don't have a cloneable wiki.
func (s *Source) wikiIsReachable(ctx context.Context, repoURL string) bool {
	wikiURL := strings.TrimSuffix(repoURL, ".git") + "/wiki"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, wikiURL, nil)
	if err != nil {
		return false
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	// If the wiki is disabled, or is enabled but has no content, the request should be redirected.
	return wikiURL == res.Request.URL.String()
}

// commitQuery represents the details required to fetch a commit.
type commitQuery struct {
	repo     string
	owner    string
	sha      string
	filename string
}

// getDiffForFileInCommit retrieves the diff for a specified file in a commit.
// If the file or its diff is not found, it returns an error.
func (s *Source) getDiffForFileInCommit(ctx context.Context, query commitQuery) (string, error) {
	commit, _, err := s.apiClient.Repositories.GetCommit(ctx, query.owner, query.repo, query.sha, nil)
	if s.handleRateLimit(err) {
		return "", fmt.Errorf("error fetching commit %s due to rate limit: %w", query.sha, err)
	}
	if err != nil {
		return "", fmt.Errorf("error fetching commit %s: %w", query.sha, err)
	}

	if len(commit.Files) == 0 {
		return "", fmt.Errorf("commit %s does not contain any files", query.sha)
	}

	res := new(strings.Builder)
	// Only return the diff if the file is in the commit.
	for _, file := range commit.Files {
		if *file.Filename != query.filename {
			continue
		}

		if file.Patch == nil {
			return "", fmt.Errorf("commit %s file %s does not have a diff", query.sha, query.filename)
		}

		if _, err := res.WriteString(*file.Patch); err != nil {
			return "", fmt.Errorf("buffer write error for commit %s file %s: %w", query.sha, query.filename, err)
		}
		res.WriteString("\n")
	}

	if res.Len() == 0 {
		return "", fmt.Errorf("commit %s does not contain patch for file %s", query.sha, query.filename)
	}

	return res.String(), nil
}

func (s *Source) normalizeRepo(repo string) (string, error) {
	// If there's a '/', assume it's a URL and try to normalize it.
	if strings.ContainsRune(repo, '/') {
		return giturl.NormalizeGithubRepo(repo)
	}

	return "", fmt.Errorf("no repositories found for %s", repo)
}
