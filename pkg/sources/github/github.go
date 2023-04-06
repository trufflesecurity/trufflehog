package github

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/go-errors/errors"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-logr/logr"
	"github.com/gobwas/glob"
	"github.com/google/go-github/v42/github"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

const (
	unauthGithubOrgRateLimt = 30
	defaultPagination       = 100
	membersAppPagination    = 500
)

type Source struct {
	name        string
	githubUser  string
	githubToken string
	sourceID    int64
	jobID       int64
	verify      bool
	repos,
	orgs,
	members,
	includeRepos,
	ignoreRepos []string
	git             *git.Git
	scanOptions     *git.ScanOptions
	httpClient      *http.Client
	log             logr.Logger
	conn            *sourcespb.GitHub
	jobPool         *errgroup.Group
	resumeInfoMutex sync.Mutex
	resumeInfoSlice []string
	apiClient       *github.Client
	mu              sync.Mutex
	publicMap       map[string]source_metadatapb.Visibility
	sources.Progress
}

func (s *Source) WithScanOptions(scanOptions *git.ScanOptions) {
	s.scanOptions = scanOptions
}

// Ensure the Source satisfies the interface at compile time
var _ sources.Source = (*Source)(nil)
var endsWithGithub = regexp.MustCompile(`github\.com/?$`)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_GITHUB
}

func (s *Source) SourceID() int64 {
	return s.sourceID
}

func (s *Source) JobID() int64 {
	return s.jobID
}

func (s *Source) UserAndToken(ctx context.Context, installationClient *github.Client) (string, string, error) {
	switch cred := s.conn.GetCredential().(type) {
	case *sourcespb.GitHub_Unauthenticated:
		// do nothing
	case *sourcespb.GitHub_GithubApp:
		id, err := strconv.ParseInt(cred.GithubApp.InstallationId, 10, 64)
		if err != nil {
			return "", "", errors.New(err)
		}
		// TODO: Check rate limit for this call.
		token, _, err := installationClient.Apps.CreateInstallationToken(
			ctx, id, &github.InstallationTokenOptions{})
		if err != nil {
			return "", "", errors.WrapPrefix(err, "unable to create installation token", 0)
		}
		return "x-access-token", token.GetToken(), nil // TODO: multiple workers request this, track the TTL
	case *sourcespb.GitHub_Token:
		var (
			ghUser *github.User
			resp   *github.Response
			err    error
		)
		for {
			ghUser, resp, err = s.apiClient.Users.Get(context.TODO(), "")
			if handled := s.handleRateLimit(err, resp); handled {
				continue
			}
			if err != nil {
				return "", "", errors.New(err)
			}
			break
		}
		return ghUser.GetLogin(), cred.Token, nil
	}

	return "", "", errors.New("unhandled credential type for token fetch")
}

// Init returns an initialized GitHub source.
func (s *Source) Init(aCtx context.Context, name string, jobID, sourceID int64, verify bool, connection *anypb.Any, concurrency int) error {
	s.log = aCtx.Logger()

	s.name = name
	s.sourceID = sourceID
	s.jobID = jobID
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)

	s.httpClient = common.RetryableHttpClientTimeout(60)
	s.apiClient = github.NewClient(s.httpClient)

	var conn sourcespb.GitHub
	err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}
	s.conn = &conn

	s.repos = s.conn.Repositories
	s.orgs = s.conn.Organizations
	s.includeRepos = s.conn.IncludeRepos
	s.ignoreRepos = s.conn.IgnoreRepos

	// Head or base should only be used with incoming webhooks
	if (len(s.conn.Head) > 0 || len(s.conn.Base) > 0) && len(s.repos) != 1 {
		return fmt.Errorf("cannot specify head or base with multiple repositories")
	}

	s.publicMap = map[string]source_metadatapb.Visibility{}

	s.git = git.NewGit(s.Type(), s.JobID(), s.SourceID(), s.name, s.verify, runtime.NumCPU(),
		func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Github{
					Github: &source_metadatapb.Github{
						Commit:     sanitizer.UTF8(commit),
						File:       sanitizer.UTF8(file),
						Email:      sanitizer.UTF8(email),
						Repository: sanitizer.UTF8(repository),
						Link:       git.GenerateLink(repository, commit, file),
						Timestamp:  sanitizer.UTF8(timestamp),
						Line:       line,
						Visibility: s.visibilityOf(repository),
					},
				},
			}
		})

	return nil
}

func (s *Source) visibilityOf(repoURL string) (visibility source_metadatapb.Visibility) {
	s.mu.Lock()
	visibility, ok := s.publicMap[repoURL]
	s.mu.Unlock()
	if ok {
		return visibility
	}

	visibility = source_metadatapb.Visibility_public
	defer func() {
		s.mu.Lock()
		s.publicMap[repoURL] = visibility
		s.mu.Unlock()
	}()
	logger := s.log.WithValues("repo", repoURL)
	logger.V(2).Info("Checking public status")
	u, err := url.Parse(repoURL)
	if err != nil {
		logger.Error(err, "Could not parse repository URL.")
		return
	}

	var resp *github.Response
	urlPathParts := strings.Split(u.Path, "/")
	switch len(urlPathParts) {
	case 2:
		// Check if repoURL is a gist.
		var gist *github.Gist
		repoName := urlPathParts[1]
		repoName = strings.TrimSuffix(repoName, ".git")
		for {
			gist, resp, err = s.apiClient.Gists.Get(context.TODO(), repoName)
			if !s.handleRateLimit(err, resp) {
				break
			}
		}
		if err != nil || gist == nil {
			if _, unauthenticated := s.conn.GetCredential().(*sourcespb.GitHub_Unauthenticated); unauthenticated {
				logger.Info("Unauthenticated scans cannot determine if a repository is private.")
				visibility = source_metadatapb.Visibility_private
			}
			logger.Error(err, "Could not get Github repository")
			return
		}
		if !(*gist.Public) {
			visibility = source_metadatapb.Visibility_private
		}
	case 3:
		var repo *github.Repository
		owner := urlPathParts[1]
		repoName := urlPathParts[2]
		repoName = strings.TrimSuffix(repoName, ".git")
		for {
			repo, resp, err = s.apiClient.Repositories.Get(context.TODO(), owner, repoName)
			if !s.handleRateLimit(err, resp) {
				break
			}
		}
		if err != nil || repo == nil {
			logger.Error(err, "Could not get Github repository")
			if _, unauthenticated := s.conn.GetCredential().(*sourcespb.GitHub_Unauthenticated); unauthenticated {
				logger.Info("Unauthenticated scans cannot determine if a repository is private.")
				visibility = source_metadatapb.Visibility_private
			}
			return
		}
		if *repo.Private {
			visibility = source_metadatapb.Visibility_private
		}
	default:
		logger.Error(fmt.Errorf("unexpected number of parts"), "RepoURL should split into 2 or 3 parts",
			"got", len(urlPathParts),
		)
	}
	return
}

func (s *Source) enumerateUnauthenticated(ctx context.Context) {
	s.apiClient = github.NewClient(s.httpClient)
	if len(s.orgs) > unauthGithubOrgRateLimt {
		s.log.Info("You may experience rate limiting when using the unauthenticated GitHub api. Consider using an authenticated scan instead.")
	}

	for _, org := range s.orgs {
		logger := s.log.WithValues("org", org)
		if err := s.addRepos(ctx, org, s.getReposByOrg); err != nil {
			logger.Error(err, "error fetching repos for org or user")
		}
		// We probably don't need to do this, since getting repos by org makes more sense?
		if err := s.addRepos(ctx, org, s.getReposByUser); err != nil {
			logger.Error(err, "error fetching repos for org or user")
		}

		if s.conn.ScanUsers {
			logger.Info("Enumerating unauthenticated does not support scanning organization members")
		}
	}
}

func (s *Source) enumerateWithToken(ctx context.Context, apiEndpoint, token string) error {
	// Needed for clones.
	s.githubToken = token

	// Needed to list repos.
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	s.httpClient.Transport = &oauth2.Transport{
		Base:   s.httpClient.Transport,
		Source: oauth2.ReuseTokenSource(nil, ts),
	}

	var err error
	// If we're using public Github, make a regular client.
	// Otherwise, make an enterprise client.
	var isGHE bool
	if apiEndpoint == "https://api.github.com" {
		s.apiClient = github.NewClient(s.httpClient)
	} else {
		isGHE = true
		s.apiClient, err = github.NewEnterpriseClient(apiEndpoint, apiEndpoint, s.httpClient)
		if err != nil {
			return errors.New(err)
		}
	}

	// TODO: this should support scanning users too

	specificScope := false

	if len(s.repos) > 0 {
		specificScope = true
	}

	var (
		ghUser *github.User
		resp   *github.Response
	)
	for {
		ghUser, resp, err = s.apiClient.Users.Get(context.TODO(), "")
		if handled := s.handleRateLimit(err, resp); handled {
			continue
		}
		if err != nil {
			return errors.New(err)
		}
		break
	}

	if len(s.orgs) > 0 {
		specificScope = true
		for _, org := range s.orgs {
			logger := s.log.WithValues("org", org)
			if err := s.addRepos(ctx, org, s.getReposByOrg); err != nil {
				logger.Error(err, "error fetching repos for org")
			}

			if s.conn.ScanUsers {
				err := s.addMembersByOrg(ctx, org)
				if err != nil {
					logger.Error(err, "Unable to add members by org")
					continue
				}
			}
		}
	}

	// If no scope was provided, enumerate them.
	if !specificScope {
		if err := s.addRepos(ctx, ghUser.GetLogin(), s.getReposByUser); err != nil {
			s.log.Error(err, "error fetching repos by user")
		}

		if isGHE {
			s.addAllVisibleOrgs(ctx)
		} else {
			// Scan for orgs is default with a token. GitHub App enumerates the repositories
			// that were assigned to it in GitHub App settings.
			s.addOrgsByUser(ctx, ghUser.GetLogin())
		}

		for _, org := range s.orgs {
			logger := s.log.WithValues("org", org)
			if err := s.addRepos(ctx, org, s.getReposByOrg); err != nil {
				logger.Error(err, "error fetching repos by org")
			}

			if err := s.addRepos(ctx, ghUser.GetLogin(), s.getReposByUser); err != nil {
				logger.Error(err, "error fetching repos for user", "user", ghUser.GetLogin())
			}

			// TODO: Test it actually works to list org gists like this.
			if err := s.addGistsByUser(ctx, org); err != nil {
				logger.Error(err, "error fetching gists by org")
			}

			if s.conn.ScanUsers {
				err := s.addMembersByOrg(ctx, org)
				if err != nil {
					logger.Error(err, "Unable to add members by org for org")
					continue
				}
			}
		}

		// If we enabled ScanUsers above, we've already added the gists for the current user and users from the orgs.
		// So if we don't have ScanUsers enabled, add the user gists as normal.
		if err := s.addGistsByUser(ctx, ghUser.GetLogin()); err != nil {
			s.log.Error(err, "error fetching gists", "user", ghUser.GetLogin())
		}
	}

	if s.conn.ScanUsers {
		s.log.Info("Adding repos", "members", len(s.members), "orgs", len(s.orgs))
		s.addReposForMembers(ctx)
		return nil
	}

	return nil
}

func (s *Source) enumerateWithApp(ctx context.Context, apiEndpoint string, app *credentialspb.GitHubApp) (installationClient *github.Client, err error) {
	installationID, err := strconv.ParseInt(app.InstallationId, 10, 64)
	if err != nil {
		return nil, errors.New(err)
	}

	appID, err := strconv.ParseInt(app.AppId, 10, 64)
	if err != nil {
		return nil, errors.New(err)
	}

	// This client is used for most APIs.
	itr, err := ghinstallation.New(
		s.httpClient.Transport,
		appID,
		installationID,
		[]byte(app.PrivateKey))
	if err != nil {
		return nil, errors.New(err)
	}
	itr.BaseURL = apiEndpoint
	s.apiClient, err = github.NewEnterpriseClient(apiEndpoint, apiEndpoint, &http.Client{Transport: itr})
	if err != nil {
		return nil, errors.New(err)
	}

	// This client is required to create installation tokens for cloning.
	// Otherwise, the required JWT is not in the request for the token :/
	appItr, err := ghinstallation.NewAppsTransport(
		s.httpClient.Transport,
		appID,
		[]byte(app.PrivateKey))
	if err != nil {
		return nil, errors.New(err)
	}
	appItr.BaseURL = apiEndpoint
	installationClient, err = github.NewEnterpriseClient(apiEndpoint, apiEndpoint, &http.Client{Transport: appItr})
	if err != nil {
		return nil, errors.New(err)
	}

	// If no repos were provided, enumerate them.
	if len(s.repos) == 0 {
		if err = s.addReposByApp(ctx); err != nil {
			return nil, err
		}

		// Check if we need to find user repos.
		if s.conn.ScanUsers {
			err := s.addMembersByApp(ctx, installationClient)
			if err != nil {
				return nil, err
			}
			s.log.Info("Scanning repos", "org_members", len(s.members))
			for _, member := range s.members {
				logger := s.log.WithValues("member", member)
				if err = s.addGistsByUser(ctx, member); err != nil {
					logger.Error(err, "error fetching gists by user")
				}
				if err := s.addRepos(ctx, member, s.getReposByUser); err != nil {
					logger.Error(err, "error fetching repos by user")
				}
			}
		}
	}

	return installationClient, nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	apiEndpoint := s.conn.Endpoint
	if len(apiEndpoint) == 0 || endsWithGithub.MatchString(apiEndpoint) {
		apiEndpoint = "https://api.github.com"
	}

	var installationClient *github.Client
	var err error

	switch cred := s.conn.GetCredential().(type) {
	case *sourcespb.GitHub_Unauthenticated:
		s.enumerateUnauthenticated(ctx)
	case *sourcespb.GitHub_Token:
		if err = s.enumerateWithToken(ctx, apiEndpoint, cred.Token); err != nil {
			return err
		}
	case *sourcespb.GitHub_GithubApp:
		if installationClient, err = s.enumerateWithApp(ctx, apiEndpoint, cred.GithubApp); err != nil {
			return err
		}
	default:
		// TODO: move this error to Init
		return errors.Errorf("Invalid configuration given for source. Name: %s, Type: %s", s.name, s.Type())
	}

	s.normalizeRepos(ctx)

	// We must sort the repos so we can resume later if necessary.
	sort.Strings(s.repos)

	for _, err := range s.scan(ctx, installationClient, chunksChan) {
		s.log.Error(err, "error scanning repository")
	}

	return nil
}

func (s *Source) scan(ctx context.Context, installationClient *github.Client, chunksChan chan *sources.Chunk) []error {
	var scanned uint64

	s.log.V(2).Info("Found repos to scan", "count", len(s.repos))

	// If there is resume information available, limit this scan to only the repos that still need scanning.
	reposToScan, progressIndexOffset := sources.FilterReposToResume(s.repos, s.GetProgress().EncodedResumeInfo)
	s.repos = reposToScan

	// Setup scan options if it wasn't provided.
	if s.scanOptions == nil {
		s.scanOptions = &git.ScanOptions{}
	}

	var scanErrs []error
	for i, repoURL := range s.repos {
		i, repoURL := i, repoURL
		s.jobPool.Go(func() error {
			if common.IsDone(ctx) {
				return nil
			}

			// TODO: set progress complete is being called concurrently with i
			s.setProgressCompleteWithRepo(i, progressIndexOffset, repoURL)
			// Ensure the repo is removed from the resume info after being scanned.
			defer func(s *Source, repoURL string) {
				s.resumeInfoMutex.Lock()
				defer s.resumeInfoMutex.Unlock()
				s.resumeInfoSlice = sources.RemoveRepoFromResumeInfo(s.resumeInfoSlice, repoURL)
			}(s, repoURL)

			if !strings.HasSuffix(repoURL, ".git") {
				scanErrs = append(scanErrs, fmt.Errorf("repo %s does not end in .git", repoURL))
				return nil
			}

			logger := s.log.WithValues("repo", repoURL)
			logger.V(2).Info(fmt.Sprintf("attempting to clone repo %d/%d", i+1, len(s.repos)))
			var path string
			var repo *gogit.Repository
			var err error

			path, repo, err = s.cloneRepo(ctx, repoURL, installationClient)
			if err != nil {
				scanErrs = append(scanErrs, err)
			}

			defer os.RemoveAll(path)
			if err != nil {
				return nil
			}

			s.scanOptions.BaseHash = s.conn.Base
			s.scanOptions.HeadHash = s.conn.Head

			if err = s.git.ScanRepo(ctx, repo, path, s.scanOptions, chunksChan); err != nil {
				logger.Error(err, "unable to scan repo, continuing")
				return nil
			}
			atomic.AddUint64(&scanned, 1)
			logger.V(2).Info(fmt.Sprintf("scanned %d/%d repos", scanned, len(s.repos)))

			return nil
		})
	}

	_ = s.jobPool.Wait()
	if len(scanErrs) == 0 {
		s.SetProgressComplete(len(s.repos), len(s.repos), "Completed Github scan", "")
	}

	return scanErrs
}

func (s *Source) cloneRepo(ctx context.Context, repoURL string, installationClient *github.Client) (string, *gogit.Repository, error) {
	var path string
	var repo *gogit.Repository
	var err error

	switch s.conn.GetCredential().(type) {
	case *sourcespb.GitHub_Unauthenticated:
		path, repo, err = git.CloneRepoUsingUnauthenticated(ctx, repoURL)
		if err != nil {
			return "", nil, fmt.Errorf("error cloning repo %s: %w", repoURL, err)
		}

	case *sourcespb.GitHub_GithubApp:
		s.githubUser, s.githubToken, err = s.UserAndToken(ctx, installationClient)
		if err != nil {
			return "", nil, fmt.Errorf("error getting token for repo %s: %w", repoURL, err)
		}

		path, repo, err = git.CloneRepoUsingToken(ctx, s.githubToken, repoURL, s.githubUser)
		if err != nil {
			return "", nil, fmt.Errorf("error cloning repo %s: %w", repoURL, err)
		}

	case *sourcespb.GitHub_Token:
		// We never refresh user provided tokens, so if we already have them, we never need to try and fetch them again.
		if s.githubUser == "" || s.githubToken == "" {
			s.githubUser, s.githubToken, err = s.UserAndToken(ctx, installationClient)
			if err != nil {
				return "", nil, fmt.Errorf("error getting token for repo %s: %w", repoURL, err)
			}
		}
		path, repo, err = git.CloneRepoUsingToken(ctx, s.githubToken, repoURL, s.githubUser)
		if err != nil {
			return "", nil, fmt.Errorf("error cloning repo %s: %w", repoURL, err)
		}
	}
	return path, repo, nil
}

// handleRateLimit returns true if a rate limit was handled
// Unauthenticated access to most github endpoints has a rate limit of 60 requests per hour.
// This will likely only be exhausted if many users/orgs are scanned without auth
func (s *Source) handleRateLimit(errIn error, res *github.Response) bool {
	limit, ok := errIn.(*github.RateLimitError)
	if !ok {
		return false
	}

	if res != nil {
		knownWait := true
		remaining, err := strconv.Atoi(res.Header.Get("x-ratelimit-remaining"))
		if err != nil {
			knownWait = false
		}
		resetTime, err := strconv.Atoi(res.Header.Get("x-ratelimit-reset"))
		if err != nil || resetTime == 0 {
			knownWait = false
		}

		if knownWait && remaining == 0 {
			waitTime := int64(resetTime) - time.Now().Unix()
			if waitTime > 0 {
				duration := time.Duration(waitTime+1) * time.Second
				s.log.V(2).Info("rate limited", "resumeTime", time.Now().Add(duration).String())
				time.Sleep(duration)
				return true
			}
		}
	}

	s.log.V(2).Info("handling rate limit (5 minutes retry)", "retry-after", limit.Message)
	time.Sleep(time.Minute * 5)
	return true
}

func (s *Source) getReposByOrg(ctx context.Context, org string) ([]string, error) {
	logger := s.log.WithValues("org", org)

	var repos []string
	opts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			PerPage: defaultPagination,
		},
	}

	var numRepos, numForks int
	for {
		someRepos, res, err := s.apiClient.Repositories.ListByOrg(ctx, org, opts)
		if err == nil {
			res.Body.Close()
		}
		if handled := s.handleRateLimit(err, res); handled {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("could not list repos for org %s: %w", org, err)
		}
		if len(someRepos) == 0 || res == nil {
			break
		}

		logger.V(2).Info("Listed repos", "page", opts.Page, "last_page", res.LastPage)
		for _, r := range someRepos {
			if s.ignoreRepo(r.GetFullName()) {
				continue
			}
			if !s.includeRepo(r.GetFullName()) {
				continue
			}

			numRepos++
			if r.GetFork() {
				numForks++
				if !s.conn.IncludeForks {
					continue
				}
			}
			repos = append(repos, r.GetCloneURL())
		}
		if res.NextPage == 0 {
			break
		}
		opts.Page = res.NextPage
	}
	logger.V(2).Info("found repos", "total", numRepos, "forks", numForks)
	return repos, nil
}

func (s *Source) addRepos(ctx context.Context, entity string, getRepos func(context.Context, string) ([]string, error)) error {
	repos, err := getRepos(ctx, entity)
	if err != nil {
		return err
	}
	// Add the repos to the set of repos.
	for _, repo := range repos {
		common.AddStringSliceItem(repo, &s.repos)
	}
	return nil
}

func (s *Source) getReposByUser(ctx context.Context, user string) ([]string, error) {
	var repos []string
	opts := &github.RepositoryListOptions{
		ListOptions: github.ListOptions{
			PerPage: 50,
		},
	}

	logger := s.log.WithValues("user", user)
	for {
		someRepos, res, err := s.apiClient.Repositories.List(ctx, user, opts)
		if err == nil {
			res.Body.Close()
		}
		if handled := s.handleRateLimit(err, res); handled {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("could not list repos for user %s: %w", user, err)
		}
		if res == nil {
			break
		}

		logger.V(2).Info("Listed repos", "page", opts.Page, "last_page", res.LastPage)
		for _, r := range someRepos {
			if s.ignoreRepo(r.GetFullName()) {
				continue
			}
			if !s.includeRepo(r.GetFullName()) {
				continue
			}

			if r.GetFork() && !s.conn.IncludeForks {
				continue
			}
			repos = append(repos, r.GetCloneURL())
		}
		if res.NextPage == 0 {
			break
		}
		opts.Page = res.NextPage
	}
	return repos, nil
}

func (s *Source) includeRepo(r string) bool {
	if len(s.includeRepos) == 0 {
		return true
	}

	logger := s.log.WithValues("repo", r)
	for _, include := range s.includeRepos {
		g, err := glob.Compile(include)
		if err != nil {
			logger.V(2).Info("invalid glob", "glob", include, "error", err)
			continue
		}
		if g.Match(r) {
			logger.V(2).Info("including repo")
			return true
		}
	}
	return false
}

func (s *Source) ignoreRepo(r string) bool {
	logger := s.log.WithValues("repo", r)
	for _, ignore := range s.ignoreRepos {
		g, err := glob.Compile(ignore)
		if err != nil {
			logger.V(2).Info("invalid glob", "glob", ignore, "error", err)
			continue
		}
		if g.Match(r) {
			logger.V(2).Info("ignoring repo")
			return true
		}
	}
	return false
}

func (s *Source) getGistsByUser(ctx context.Context, user string) ([]string, error) {
	var gistURLs []string
	gistOpts := &github.GistListOptions{}
	logger := s.log.WithValues("user", user)
	for {
		gists, res, err := s.apiClient.Gists.List(ctx, user, gistOpts)
		if err == nil {
			res.Body.Close()
		}
		if handled := s.handleRateLimit(err, res); handled {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("could not list gists for user %s: %w", user, err)
		}
		for _, gist := range gists {
			gistURLs = append(gistURLs, gist.GetGitPullURL())
		}
		if res == nil || res.NextPage == 0 {
			break
		}
		logger.V(2).Info("Listed gists", "page", gistOpts.Page, "last_page", res.LastPage)
		gistOpts.Page = res.NextPage
	}
	return gistURLs, nil
}

func (s *Source) addGistsByUser(ctx context.Context, user string) error {
	gists, err := s.getGistsByUser(ctx, user)
	if err != nil {
		return err
	}
	// add the gists to the set of repos
	for _, gist := range gists {
		common.AddStringSliceItem(gist, &s.repos)
	}
	return nil
}

func (s *Source) addMembersByApp(ctx context.Context, installationClient *github.Client) error {
	opts := &github.ListOptions{
		PerPage: membersAppPagination,
	}

	// TODO: Check rate limit for this call.
	installs, _, err := installationClient.Apps.ListInstallations(ctx, opts)
	if err != nil {
		return fmt.Errorf("could not enumerate installed orgs: %w", err)
	}

	for _, org := range installs {
		if org.Account.GetType() != "Organization" {
			continue
		}
		if err := s.addMembersByOrg(ctx, *org.Account.Login); err != nil {
			return err
		}
	}

	return nil
}

func (s *Source) addReposByApp(ctx context.Context) error {
	// Authenticated enumeration of repos
	opts := &github.ListOptions{
		PerPage: defaultPagination,
	}
	for {
		someRepos, res, err := s.apiClient.Apps.ListRepos(ctx, opts)
		if err == nil {
			res.Body.Close()
		}
		if handled := s.handleRateLimit(err, res); handled {
			continue
		}
		if err != nil {
			return errors.WrapPrefix(err, "unable to list repositories", 0)
		}
		if res == nil {
			break
		}
		s.log.V(2).Info("Listed repos for app", "page", opts.Page, "last_page", res.LastPage)
		for _, r := range someRepos.Repositories {
			if r.GetFork() && !s.conn.IncludeForks {
				continue
			}
			common.AddStringSliceItem(r.GetCloneURL(), &s.repos)
			s.log.V(2).Info("Enumerated repo", "repo", r.GetCloneURL())
		}
		if res.NextPage == 0 {
			break
		}
		opts.Page = res.NextPage
	}
	return nil
}

func (s *Source) addAllVisibleOrgs(ctx context.Context) {
	s.log.V(2).Info("enumerating all visible organizations on GHE")
	// Enumeration on this endpoint does not use pages it uses a since ID.
	// The endpoint will return organizations with an ID greater than the given since ID.
	// Empty org response is our cue to break the enumeration loop.
	orgOpts := &github.OrganizationsListOptions{
		Since: 0,
		ListOptions: github.ListOptions{
			PerPage: defaultPagination,
		},
	}
	for {
		orgs, resp, err := s.apiClient.Organizations.ListAll(ctx, orgOpts)
		if err == nil {
			resp.Body.Close()
		}
		if handled := s.handleRateLimit(err, resp); handled {
			continue
		}
		if err != nil {
			s.log.Error(err, "Could not list all organizations")
			return
		}
		if len(orgs) == 0 {
			break
		}
		lastOrgID := *orgs[len(orgs)-1].ID
		s.log.V(2).Info(fmt.Sprintf("listed organization IDs %d through %d", orgOpts.Since, lastOrgID))
		orgOpts.Since = lastOrgID

		for _, org := range orgs {
			var name string
			if org.Name != nil {
				name = *org.Name
			} else if org.Login != nil {
				name = *org.Login
			} else {
				continue
			}
			s.log.V(2).Info("adding organization for repository enumeration", "id", org.ID, "org", name)
			common.AddStringSliceItem(name, &s.orgs)
		}
	}
}

func (s *Source) addOrgsByUser(ctx context.Context, user string) {
	orgOpts := &github.ListOptions{
		PerPage: defaultPagination,
	}
	logger := s.log.WithValues("user", user)
	for {
		orgs, resp, err := s.apiClient.Organizations.List(ctx, "", orgOpts)
		if err == nil {
			resp.Body.Close()
		}
		if handled := s.handleRateLimit(err, resp); handled {
			continue
		}
		if err != nil {
			logger.Error(err, "Could not list organizations")
			return
		}
		if resp == nil {
			break
		}
		logger.V(2).Info("Listed orgs", "page", orgOpts.Page, "last_page", resp.LastPage)
		for _, org := range orgs {
			var name string
			if org.Login != nil {
				name = *org.Login
			} else {
				continue
			}
			common.AddStringSliceItem(name, &s.orgs)
		}
		if resp.NextPage == 0 {
			break
		}
		orgOpts.Page = resp.NextPage
	}
}

func (s *Source) addMembersByOrg(ctx context.Context, org string) error {
	opts := &github.ListMembersOptions{
		PublicOnly: false,
		ListOptions: github.ListOptions{
			PerPage: membersAppPagination,
		},
	}

	logger := s.log.WithValues("org", org)
	for {
		members, res, err := s.apiClient.Organizations.ListMembers(ctx, org, opts)
		if err == nil {
			defer res.Body.Close()
		}
		if handled := s.handleRateLimit(err, res); handled {
			continue
		}
		if err != nil || len(members) == 0 {
			return errors.New("Could not list organization members: account may not have access to list organization members")
		}
		if res == nil {
			break
		}
		logger.V(2).Info("Listed members", "page", opts.Page, "last_page", res.LastPage)
		for _, m := range members {
			usr := m.Login
			if usr == nil || *usr == "" {
				continue
			}
			common.AddStringSliceItem(*usr, &s.members)
		}
		if res.NextPage == 0 {
			break
		}
		opts.Page = res.NextPage
	}

	return nil
}

func (s *Source) addReposForMembers(ctx context.Context) {
	s.log.Info("Fetching repos from members", "members", len(s.members))
	for _, member := range s.members {
		if err := s.addGistsByUser(ctx, member); err != nil {
			s.log.Info("Unable to fetch gists by user", "user", member, "error", err)
		}
		if err := s.addRepos(ctx, member, s.getReposByUser); err != nil {
			s.log.Info("Unable to fetch repos by user", "user", member, "error", err)
		}
	}
}

func (s *Source) normalizeRepos(ctx context.Context) {
	// TODO: Add check/fix for repos that are missing scheme
	normalizedRepos := map[string]struct{}{}
	for _, repo := range s.repos {
		// If there's a '/', assume it's a URL and try to normalize it.
		if strings.ContainsRune(repo, '/') {
			repoNormalized, err := giturl.NormalizeGithubRepo(repo)
			if err != nil {
				s.log.Info("Repo not in expected format", "repo", repo, "error", err)
				continue
			}
			normalizedRepos[repoNormalized] = struct{}{}
			continue
		}
		// Otherwise, assume it's a user and enumerate repositories and gists.
		if repos, err := s.getReposByUser(ctx, repo); err == nil {
			for _, repo := range repos {
				normalizedRepos[repo] = struct{}{}
			}
		}
		if gists, err := s.getGistsByUser(ctx, repo); err == nil {
			for _, gist := range gists {
				normalizedRepos[gist] = struct{}{}
			}
		}
	}

	// Replace s.repos.
	s.repos = s.repos[:0]
	for key := range normalizedRepos {
		s.repos = append(s.repos, key)
	}
}

// setProgressCompleteWithRepo calls the s.SetProgressComplete after safely setting up the encoded resume info string.
func (s *Source) setProgressCompleteWithRepo(index int, offset int, repoURL string) {
	s.resumeInfoMutex.Lock()
	defer s.resumeInfoMutex.Unlock()

	// Add the repoURL to the resume info slice.
	s.resumeInfoSlice = append(s.resumeInfoSlice, repoURL)
	sort.Strings(s.resumeInfoSlice)

	// Make the resume info string from the slice.
	encodedResumeInfo := sources.EncodeResumeInfo(s.resumeInfoSlice)

	s.SetProgressComplete(index+offset, len(s.repos)+offset, fmt.Sprintf("Repo: %s", repoURL), encodedResumeInfo)
}
