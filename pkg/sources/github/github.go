package github

import (
	"fmt"
	"net/http"
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
	"github.com/google/go-github/v42/github"
	log "github.com/sirupsen/logrus"
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
	name            string
	sourceID        int64
	jobID           int64
	verify          bool
	repos           []string
	orgs            []string
	members         []string
	git             *git.Git
	httpClient      *http.Client
	aCtx            context.Context
	log             *log.Entry
	token           string
	conn            *sourcespb.GitHub
	jobPool         *errgroup.Group
	resumeInfoSlice []string
	resumeInfoMutex sync.Mutex
	sources.Progress
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

func (s *Source) Token(ctx context.Context, installationClient *github.Client) (string, error) {
	switch cred := s.conn.GetCredential().(type) {
	case *sourcespb.GitHub_Unauthenticated:
		// do nothing
	case *sourcespb.GitHub_GithubApp:
		id, err := strconv.ParseInt(cred.GithubApp.InstallationId, 10, 64)
		if err != nil {
			return "", errors.New(err)
		}
		token, _, err := installationClient.Apps.CreateInstallationToken(
			ctx, id, &github.InstallationTokenOptions{})
		if err != nil {
			return "", errors.WrapPrefix(err, "unable to create installation token", 0)
		}
		return token.GetToken(), nil // TODO: multiple workers request this, track the TTL
	case *sourcespb.GitHub_Token:
		return cred.Token, nil
	}

	return "", errors.New("unhandled credential type for token fetch")
}

// Init returns an initialized GitHub source.
func (s *Source) Init(aCtx context.Context, name string, jobID, sourceID int64, verify bool, connection *anypb.Any, concurrency int) error {
	s.log = log.WithField("source", s.Type()).WithField("name", name)

	s.aCtx = aCtx
	s.name = name
	s.sourceID = sourceID
	s.jobID = jobID
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)

	s.httpClient = common.SaneHttpClient()

	var conn sourcespb.GitHub
	err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}
	s.conn = &conn

	s.repos = s.conn.Repositories
	s.orgs = s.conn.Organizations

	// Head or base should only be used with incoming webhooks
	if (len(s.conn.Head) > 0 || len(s.conn.Base) > 0) && len(s.repos) != 1 {
		return fmt.Errorf("cannot specify head or base with multiple repositories")
	}

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
					},
				},
			}
		})

	return nil
}

func (s *Source) enumerateUnauthenticated(ctx context.Context) (*github.Client, error) {
	apiClient := github.NewClient(s.httpClient)
	if len(s.orgs) > unauthGithubOrgRateLimt {
		log.Warn("You may experience rate limiting when using the unauthenticated GitHub api. Consider using an authenticated scan instead.")
	}

	user, _, err := apiClient.Users.Get(context.TODO(), "")
	if err != nil {
		return nil, fmt.Errorf("unable to get user: %v", err)
	}
	for _, org := range s.orgs {
		errOrg := s.addRepos(ctx, apiClient, org, s.getReposByOrg)
		errUser := s.addRepos(ctx, apiClient, user.GetLogin(), s.getReposByUser)
		if errOrg != nil && errUser != nil {
			log.WithError(errOrg).Error("error fetching repos for org or user: ", org)
		}
	}
	return apiClient, nil
}

func (s *Source) enumerateWithToken(ctx context.Context, apiEndpoint, token string) (*github.Client, error) {
	// Needed for clones.
	s.token = token

	// Needed to list repos.
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(context.TODO(), ts)

	var err error
	// If we're using public Github, make a regular client.
	// Otherwise, make an enterprise client.
	var isGHE bool
	var apiClient *github.Client
	if apiEndpoint == "https://api.github.com" {
		apiClient = github.NewClient(tc)
	} else {
		isGHE = true
		apiClient, err = github.NewEnterpriseClient(apiEndpoint, apiEndpoint, tc)
		if err != nil {
			return nil, errors.New(err)
		}
	}

	// TODO: this should support scanning users too

	specificScope := false

	if len(s.repos) > 0 {
		specificScope = true
	}

	user, _, err := apiClient.Users.Get(context.TODO(), "")
	if err != nil {
		return nil, errors.New(err)
	}

	if len(s.orgs) > 0 {
		specificScope = true
		for _, org := range s.orgs {
			errOrg := s.addRepos(ctx, apiClient, org, s.getReposByOrg)
			errUser := s.addRepos(ctx, apiClient, user.GetLogin(), s.getReposByUser)
			if errOrg != nil && errUser != nil {
				log.WithError(errOrg).Error("error fetching repos for org or user: ", org)
			}
		}
	}

	// If no scope was provided, enumerate them.
	if !specificScope {
		if err := s.addRepos(ctx, apiClient, user.GetLogin(), s.getReposByUser); err != nil {
			log.WithError(err).Error("error fetching repos by user")
		}

		if isGHE {
			s.addAllVisibleOrgs(ctx, apiClient)
		} else {
			// Scan for orgs is default with a token. GitHub App enumerates the repositories
			// that were assigned to it in GitHub App settings.
			s.addOrgsByUser(ctx, apiClient, user.GetLogin())
		}

		for _, org := range s.orgs {
			if err := s.addRepos(ctx, apiClient, org, s.getReposByOrg); err != nil {
				log.WithError(err).Error("error fetching repos by org")
			}
		}
	}

	if err := s.addGistsByUser(ctx, apiClient, user.GetLogin()); err != nil {
		return nil, err
	}
	for _, org := range s.orgs {
		// TODO: Test it actually works to list org gists like this.
		if err := s.addGistsByUser(ctx, apiClient, org); err != nil {
			log.WithError(err).Errorf("error fetching gists by org: %s", org)
		}
	}
	return apiClient, nil
}

func (s *Source) enumerateWithApp(ctx context.Context, apiEndpoint string, app *credentialspb.GitHubApp) (apiClient, installationClient *github.Client, err error) {
	installationID, err := strconv.ParseInt(app.InstallationId, 10, 64)
	if err != nil {
		return nil, nil, errors.New(err)
	}

	appID, err := strconv.ParseInt(app.AppId, 10, 64)
	if err != nil {
		return nil, nil, errors.New(err)
	}

	// This client is used for most APIs.
	itr, err := ghinstallation.New(
		s.httpClient.Transport,
		appID,
		installationID,
		[]byte(app.PrivateKey))
	if err != nil {
		return nil, nil, errors.New(err)
	}
	itr.BaseURL = apiEndpoint
	apiClient, err = github.NewEnterpriseClient(apiEndpoint, apiEndpoint, &http.Client{Transport: itr})
	if err != nil {
		return nil, nil, errors.New(err)
	}

	// This client is required to create installation tokens for cloning.
	// Otherwise, the required JWT is not in the request for the token :/
	appItr, err := ghinstallation.NewAppsTransport(
		s.httpClient.Transport,
		appID,
		[]byte(app.PrivateKey))
	if err != nil {
		return nil, nil, errors.New(err)
	}
	appItr.BaseURL = apiEndpoint
	installationClient, err = github.NewEnterpriseClient(apiEndpoint, apiEndpoint, &http.Client{Transport: appItr})
	if err != nil {
		return nil, nil, errors.New(err)
	}

	// If no repos were provided, enumerate them.
	if len(s.repos) == 0 {
		if err = s.addReposByApp(ctx, apiClient); err != nil {
			return nil, nil, err
		}

		// Check if we need to find user repos.
		if s.conn.ScanUsers {
			err := s.addMembersByApp(ctx, installationClient, apiClient)
			if err != nil {
				return nil, nil, err
			}
			log.Infof("Scanning repos from %v organization members.", len(s.members))
			for _, member := range s.members {
				if err = s.addGistsByUser(ctx, apiClient, member); err != nil {
					return nil, nil, err
				}
				if err := s.addRepos(ctx, apiClient, member, s.getReposByUser); err != nil {
					log.WithError(err).Error("error fetching repos by user")
				}
			}
		}
	}

	return apiClient, installationClient, nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	apiEndpoint := s.conn.Endpoint
	if len(apiEndpoint) == 0 || endsWithGithub.MatchString(apiEndpoint) {
		apiEndpoint = "https://api.github.com"
	}

	var apiClient, installationClient *github.Client
	var err error

	switch cred := s.conn.GetCredential().(type) {
	case *sourcespb.GitHub_Unauthenticated:
		if apiClient, err = s.enumerateUnauthenticated(ctx); err != nil {
			return fmt.Errorf("error enumerating unauthenticated: %w", err)
		}
	case *sourcespb.GitHub_Token:
		if apiClient, err = s.enumerateWithToken(ctx, apiEndpoint, cred.Token); err != nil {
			return err
		}
	case *sourcespb.GitHub_GithubApp:
		if apiClient, installationClient, err = s.enumerateWithApp(ctx, apiEndpoint, cred.GithubApp); err != nil {
			return err
		}
	default:
		// TODO: move this error to Init
		return errors.Errorf("Invalid configuration given for source. Name: %s, Type: %s", s.name, s.Type())
	}

	s.normalizeRepos(ctx, apiClient)

	// We must sort the repos so we can resume later if necessary.
	sort.Strings(s.repos)

	errs := s.scan(ctx, installationClient, chunksChan)
	for _, err := range errs {
		log.WithError(err).Error("error scanning repository")
	}
	return nil
}

func (s *Source) scan(ctx context.Context, installationClient *github.Client, chunksChan chan *sources.Chunk) []error {
	var scanned uint64

	log.Debugf("Found %v total repos to scan", len(s.repos))

	// If there is resume information available, limit this scan to only the repos that still need scanning.
	reposToScan, progressIndexOffset := sources.FilterReposToResume(s.repos, s.GetProgress().EncodedResumeInfo)
	s.repos = reposToScan

	var scanErrs []error
	for i, repoURL := range s.repos {
		repoURL := repoURL
		s.jobPool.Go(func() error {
			if common.IsDone(ctx) {
				return nil
			}

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

			s.log.WithField("repo", repoURL).Debugf("attempting to clone repo %d/%d", i+1, len(s.repos))
			var path string
			var repo *gogit.Repository
			var err error

			switch s.conn.GetCredential().(type) {
			case *sourcespb.GitHub_Unauthenticated:
				path, repo, err = git.CloneRepoUsingUnauthenticated(repoURL)
				if err != nil {
					scanErrs = append(scanErrs, fmt.Errorf("error cloning repo %s: %w", repoURL, err))
				}
			default:
				var token string
				token, err = s.Token(ctx, installationClient)
				if err != nil {
					scanErrs = append(scanErrs, fmt.Errorf("error getting token for repo %s: %w", repoURL, err))
				}
				path, repo, err = git.CloneRepoUsingToken(token, repoURL, "")
				if err != nil {
					scanErrs = append(scanErrs, fmt.Errorf("error cloning repo %s: %w", repoURL, err))
				}
			}

			defer os.RemoveAll(path)
			if err != nil {
				return nil
			}
			// Base and head will only exist from incoming webhooks.
			scanOptions := git.NewScanOptions(
				git.ScanOptionBaseHash(s.conn.Base),
				git.ScanOptionHeadCommit(s.conn.Head),
			)

			if err = s.git.ScanRepo(ctx, repo, path, scanOptions, chunksChan); err != nil {
				log.WithError(err).Errorf("unable to scan repo, continuing")
				return nil
			}
			atomic.AddUint64(&scanned, 1)
			log.Debugf("scanned %d/%d repos", scanned, len(s.repos))

			return nil
		})
	}

	_ = s.jobPool.Wait()
	if len(scanErrs) == 0 {
		s.SetProgressComplete(len(s.repos), len(s.repos), "Completed Github scan", "")
	}

	return scanErrs
}

// handleRateLimit returns true if a rate limit was handled
// Unauthenticated access to most github endpoints has a rate limit of 60 requests per hour.
// This will likely only be exhausted if many users/orgs are scanned without auth
func handleRateLimit(errIn error, res *github.Response) bool {
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
				log.WithField("resumeTime", time.Now().Add(duration).String()).Debugf("rate limited")
				time.Sleep(duration)
				return true
			}
		}
	}

	log.WithField("retry-after", limit.Message).Debug("handling rate limit (5 minutes retry)")
	time.Sleep(time.Minute * 5)
	return true
}

func (s *Source) getReposByOrg(ctx context.Context, apiClient *github.Client, org string) ([]string, error) {
	logger := s.log.WithField("org", org)

	var repos []string
	opts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			PerPage: defaultPagination,
		},
	}
	var numRepos, numForks int
	for {
		someRepos, res, err := apiClient.Repositories.ListByOrg(ctx, org, opts)
		if err == nil {
			defer res.Body.Close()
		}
		if handled := handleRateLimit(err, res); handled {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("could not list repos for org %s: %w", org, err)
		}
		logger.Debugf("listed repos page %d/%d", opts.Page, res.LastPage)
		if len(someRepos) == 0 {
			break
		}
		for _, r := range someRepos {
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
	logger.Debugf("found %d repos (%d forks)", numRepos, numForks)
	return repos, nil
}

func (s *Source) addRepos(ctx context.Context, client *github.Client, entity string, getRepos func(context.Context, *github.Client, string) ([]string, error)) error {
	repos, err := getRepos(ctx, client, entity)
	if err != nil {
		return err
	}
	// Add the repos to the set of repos.
	for _, repo := range repos {
		common.AddStringSliceItem(repo, &s.repos)
	}
	return nil
}

func (s *Source) getReposByUser(ctx context.Context, apiClient *github.Client, user string) ([]string, error) {
	var repos []string
	opts := &github.RepositoryListOptions{
		ListOptions: github.ListOptions{
			PerPage: 50,
		},
	}
	for {
		someRepos, res, err := apiClient.Repositories.List(ctx, user, opts)
		if err == nil {
			defer res.Body.Close()
		}
		if handled := handleRateLimit(err, res); handled {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("could not list repos for user %s: %w", user, err)
		}
		for _, r := range someRepos {
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

func (s *Source) getGistsByUser(ctx context.Context, apiClient *github.Client, user string) ([]string, error) {
	var gistURLs []string
	gistOpts := &github.GistListOptions{}
	for {
		gists, resp, err := apiClient.Gists.List(ctx, user, gistOpts)
		if err == nil {
			defer resp.Body.Close()
		}
		if handled := handleRateLimit(err, resp); handled {
			continue
		}
		if err != nil {
			log.WithError(err).Warnf("could not list repos for user %s", user)
			return nil, fmt.Errorf("could not list repos for user %s: %w", user, err)
		}
		for _, gist := range gists {
			gistURLs = append(gistURLs, gist.GetGitPullURL())
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		gistOpts.Page = resp.NextPage
	}
	return gistURLs, nil
}

func (s *Source) addGistsByUser(ctx context.Context, apiClient *github.Client, user string) error {
	gists, err := s.getGistsByUser(ctx, apiClient, user)
	if err != nil {
		return err
	}
	// add the gists to the set of repos
	for _, gist := range gists {
		common.AddStringSliceItem(gist, &s.repos)
	}
	return nil
}

func (s *Source) addMembersByApp(ctx context.Context, installationClient *github.Client, apiClient *github.Client) error {
	opts := &github.ListOptions{
		PerPage: membersAppPagination,
	}
	optsOrg := &github.ListMembersOptions{
		PublicOnly:  false,
		ListOptions: *opts,
	}

	installs, _, err := installationClient.Apps.ListInstallations(ctx, opts)
	if err != nil {
		log.WithError(err).Warn("Could not enumerate organizations using user")
		return err
	}
	for _, org := range installs {
		for {
			members, res, err := apiClient.Organizations.ListMembers(ctx, *org.Account.Login, optsOrg)
			if err == nil {
				defer res.Body.Close()
			}
			if handled := handleRateLimit(err, res); handled {
				continue
			}
			if err != nil || len(members) == 0 {
				errText := "Could not list organization members: Please install on an organization. Otherwise, this is an older version of the Github app, please delete and re-add this source!"
				log.WithError(err).Warnf(errText)
				return errors.New(errText)
			}
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
	}

	return nil
}

func (s *Source) addReposByApp(ctx context.Context, apiClient *github.Client) error {
	// Authenticated enumeration of repos
	opts := &github.ListOptions{
		PerPage: defaultPagination,
	}
	for {
		someRepos, res, err := apiClient.Apps.ListRepos(ctx, opts)
		if err == nil {
			defer res.Body.Close()
		}
		if handled := handleRateLimit(err, res); handled {
			continue
		}
		if err != nil {
			return errors.WrapPrefix(err, "unable to list repositories", 0)
		}
		for _, r := range someRepos.Repositories {
			if r.GetFork() && !s.conn.IncludeForks {
				continue
			}
			common.AddStringSliceItem(r.GetCloneURL(), &s.repos)
		}
		if res.NextPage == 0 {
			break
		}
		opts.Page = res.NextPage
	}
	return nil
}

func (s *Source) addAllVisibleOrgs(ctx context.Context, apiClient *github.Client) {
	s.log.Debug("enumerating all visible organizations on GHE")
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
		orgs, resp, err := apiClient.Organizations.ListAll(ctx, orgOpts)
		if err == nil {
			defer resp.Body.Close()
		}
		if handled := handleRateLimit(err, resp); handled {
			continue
		}
		if err != nil {
			log.WithError(err).Errorf("Could not list all organizations")
			return
		}
		if len(orgs) == 0 {
			break
		}
		lastOrgID := *orgs[len(orgs)-1].ID
		s.log.Debugf("listed organization IDs %d through %d", orgOpts.Since, lastOrgID)
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
			s.log.Debugf("adding organization %d for repository enumeration: %s", org.ID, name)
			common.AddStringSliceItem(name, &s.orgs)
		}
	}
}

func (s *Source) addOrgsByUser(ctx context.Context, apiClient *github.Client, user string) {
	orgOpts := &github.ListOptions{
		PerPage: defaultPagination,
	}
	for {
		orgs, resp, err := apiClient.Organizations.List(ctx, "", orgOpts)
		if err == nil {
			defer resp.Body.Close()
		}
		if handled := handleRateLimit(err, resp); handled {
			continue
		}
		if err != nil {
			log.WithError(err).Errorf("Could not list organizations for %s", user)
			return
		}
		for _, org := range orgs {
			var name string
			if org.Name != nil {
				name = *org.Name
			} else if org.Login != nil {
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

func (s *Source) normalizeRepos(ctx context.Context, apiClient *github.Client) {
	// TODO: Add check/fix for repos that are missing scheme
	normalizedRepos := map[string]struct{}{}
	for _, repo := range s.repos {
		// If there's a '/', assume it's a URL and try to normalize it.
		if strings.ContainsRune(repo, '/') {
			repoNormalized, err := giturl.NormalizeGithubRepo(repo)
			if err != nil {
				log.WithError(err).Warnf("Repo not in expected format: %s", repo)
				continue
			}
			normalizedRepos[repoNormalized] = struct{}{}
			continue
		}
		// Otherwise, assume it's a user and enumerate repositories and gists.
		if repos, err := s.getReposByUser(ctx, apiClient, repo); err == nil {
			for _, repo := range repos {
				normalizedRepos[repo] = struct{}{}
			}
		}
		if gists, err := s.getGistsByUser(ctx, apiClient, repo); err == nil {
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
