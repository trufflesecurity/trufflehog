package github

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"runtime"
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
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type Source struct {
	name       string
	sourceID   int64
	jobID      int64
	verify     bool
	repos      []string
	orgs       []string
	members    []string
	git        *git.Git
	httpClient *http.Client
	aCtx       context.Context
	sources.Progress
	log    *log.Entry
	token  string
	conn   *sourcespb.GitHub
	jobSem *semaphore.Weighted
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
	s.jobSem = semaphore.NewWeighted(int64(concurrency))

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

func (s *Source) enumerateUnauthenticated(ctx context.Context) *github.Client {
	apiClient := github.NewClient(s.httpClient)
	if len(s.orgs) > 30 {
		log.Warn("You may experience rate limiting when using the unauthenticated GitHub api. Consider using an authenticated scan instead.")
	}

	for _, org := range s.orgs {
		errOrg := s.addReposByOrg(ctx, apiClient, org)
		errUser := s.addReposByUser(ctx, apiClient, org)
		if errOrg != nil && errUser != nil {
			log.WithError(errOrg).Error("error fetching repos for org or user: ", org)
		}
	}
	return apiClient
}

func (s *Source) enumerateWithToken(ctx context.Context, apiEndpoint, token string) (*github.Client, error) {
	// needed for clones
	s.token = token

	// needed to list repos
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(context.TODO(), ts)

	var err error
	// If we're using public github, make a regular client.
	// Otherwise make an enterprise client
	var apiClient *github.Client
	if apiEndpoint == "https://api.github.com" {
		apiClient = github.NewClient(tc)
	} else {
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

	if len(s.orgs) > 0 {
		specificScope = true
		for _, org := range s.orgs {
			errOrg := s.addReposByOrg(ctx, apiClient, org)
			errUser := s.addReposByUser(ctx, apiClient, org)
			if errOrg != nil && errUser != nil {
				log.WithError(errOrg).Error("error fetching repos for org or user: ", org)
			}
		}
	}

	user, _, err := apiClient.Users.Get(context.TODO(), "")
	if err != nil {
		return nil, errors.New(err)
	}

	// If no scope was provided, enumerate them
	if !specificScope {
		if err := s.addReposByUser(ctx, apiClient, user.GetLogin()); err != nil {
			log.WithError(err).Error("error fetching repos by user")
		}
		// Scan for orgs is default with a token. GitHub App enumerates the repositories
		// that were assigned to it in GitHub App settings.
		s.addOrgsByUser(ctx, apiClient, user.GetLogin())
		for _, org := range s.orgs {
			if err := s.addReposByOrg(ctx, apiClient, org); err != nil {
				log.WithError(err).Error("error fetching repos by org")
			}
		}
	}

	s.addGistsByUser(ctx, apiClient, user.GetLogin())
	for _, org := range s.orgs {
		// TODO: Test it actually works to list org gists like this.
		s.addGistsByUser(ctx, apiClient, org)
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

	// This client is used for most APIs
	itr, err := ghinstallation.New(
		common.SaneHttpClient().Transport,
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

	// This client is required to create installation tokens for cloning.. Otherwise the required JWT is not in the
	// request for the token :/
	appItr, err := ghinstallation.NewAppsTransport(
		common.SaneHttpClient().Transport,
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

	// If no repos were provided, enumerate them
	if len(s.repos) == 0 {
		err = s.addReposByApp(ctx, apiClient)
		if err != nil {
			return nil, nil, err
		}

		// check if we need to find user repos
		if s.conn.ScanUsers {
			err := s.addMembersByApp(ctx, installationClient, apiClient)
			if err != nil {
				return nil, nil, err
			}
			log.Infof("Scanning repos from %v organization members.", len(s.members))
			for _, member := range s.members {
				s.addGistsByUser(ctx, apiClient, member)
				if err := s.addReposByUser(ctx, apiClient, member); err != nil {
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

	switch cred := s.conn.GetCredential().(type) {
	case *sourcespb.GitHub_Unauthenticated:
		apiClient = s.enumerateUnauthenticated(ctx)
	case *sourcespb.GitHub_Token:
		var err error
		if apiClient, err = s.enumerateWithToken(ctx, apiEndpoint, cred.Token); err != nil {
			return err
		}
	case *sourcespb.GitHub_GithubApp:
		var err error
		if apiClient, installationClient, err = s.enumerateWithApp(ctx, apiEndpoint, cred.GithubApp); err != nil {
			return err
		}
	default:
		// TODO: move this error to Init
		return errors.Errorf("Invalid configuration given for source. Name: %s, Type: %s", s.name, s.Type())
	}

	s.normalizeRepos(ctx, apiClient)

	if _, ok := os.LookupEnv("DO_NOT_RANDOMIZE"); !ok {
		// Randomize channel scan order on each scan
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(s.repos), func(i, j int) { s.repos[i], s.repos[j] = s.repos[j], s.repos[i] })
	}

	return s.scan(ctx, installationClient, chunksChan)
}

func (s *Source) scan(ctx context.Context, installationClient *github.Client, chunksChan chan *sources.Chunk) error {
	var scanned uint64

	log.Debugf("Found %v total repos to scan", len(s.repos))
	wg := sync.WaitGroup{}
	errs := make(chan error, 1)
	reportErr := func(err error) {
		// save the error if there's room, otherwise log and drop it
		select {
		case errs <- err:
		default:
			log.WithError(err).Warn("dropping error")
		}
	}

	for i, repoURL := range s.repos {
		if err := s.jobSem.Acquire(ctx, 1); err != nil {
			// Acquire blocks until it can acquire the semaphore or returns an
			// error if the context is finished
			log.WithError(err).Debug("could not acquire semaphore")
			reportErr(err)
			break
		}
		wg.Add(1)
		go func(ctx context.Context, repoURL string, i int) {
			defer s.jobSem.Release(1)
			defer wg.Done()

			s.SetProgressComplete(i, len(s.repos), fmt.Sprintf("Repo: %s", repoURL), "")

			if !strings.HasSuffix(repoURL, ".git") {
				return
			}

			s.log.WithField("repo", repoURL).Debugf("attempting to clone repo %d/%d", i+1, len(s.repos))
			var path string
			var repo *gogit.Repository
			var err error

			switch s.conn.GetCredential().(type) {
			case *sourcespb.GitHub_Unauthenticated:
				path, repo, err = git.CloneRepoUsingUnauthenticated(repoURL)
			default:
				var token string
				token, err = s.Token(ctx, installationClient)
				if err != nil {
					reportErr(err)
					return
				}
				path, repo, err = git.CloneRepoUsingToken(token, repoURL, "clone")
			}

			defer os.RemoveAll(path)
			if err != nil {
				log.WithError(err).Errorf("unable to clone repo (%s), continuing", repoURL)
				return
			}
			// Base and head will only exist from incoming webhooks.
			scanOptions := git.NewScanOptions(
				git.ScanOptionBaseHash(s.conn.Base),
				git.ScanOptionHeadCommit(s.conn.Head),
			)

			err = s.git.ScanRepo(ctx, repo, path, scanOptions, chunksChan)
			if err != nil {
				log.WithError(err).Errorf("unable to scan repo, continuing")
			}
			atomic.AddUint64(&scanned, 1)
			log.Debugf("scanned %d/%d repos", scanned, len(s.repos))
		}(ctx, repoURL, i)
	}

	wg.Wait()

	// This only returns first error which is what we did prior to concurrency
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
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
	repos := []string{}
	opts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
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
	log.WithField("org", org).Debugf("Found %d repos (%d forks)", numRepos, numForks)
	return repos, nil
}

func (s *Source) addReposByOrg(ctx context.Context, apiClient *github.Client, org string) error {
	repos, err := s.getReposByOrg(ctx, apiClient, org)
	if err != nil {
		return err
	}
	// add the repos to the set of repos
	for _, repo := range repos {
		common.AddStringSliceItem(repo, &s.repos)
	}
	return nil
}

func (s *Source) getReposByUser(ctx context.Context, apiClient *github.Client, user string) ([]string, error) {
	repos := []string{}
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

func (s *Source) addReposByUser(ctx context.Context, apiClient *github.Client, user string) error {
	repos, err := s.getReposByUser(ctx, apiClient, user)
	if err != nil {
		return err
	}
	// add the repos to the set of repos
	for _, repo := range repos {
		common.AddStringSliceItem(repo, &s.repos)
	}
	return nil
}

func (s *Source) getGistsByUser(ctx context.Context, apiClient *github.Client, user string) ([]string, error) {
	gistURLs := []string{}
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
		PerPage: 500,
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
		PerPage: 100,
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

func (s *Source) addOrgsByUser(ctx context.Context, apiClient *github.Client, user string) {
	orgOpts := &github.ListOptions{
		PerPage: 100,
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
		// if there's a '/', assume it's a URL and try to normalize it
		if strings.ContainsRune(repo, '/') {
			repoNormalized, err := giturl.NormalizeGithubRepo(repo)
			if err != nil {
				log.WithError(err).Warnf("Repo not in expected format: %s", repo)
				continue
			}
			normalizedRepos[repoNormalized] = struct{}{}
			continue
		}
		// otherwise, assume it's a user and enumerate repositories and gists
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

	// replace s.repos
	s.repos = s.repos[:0]
	for key := range normalizedRepos {
		s.repos = append(s.repos, key)
	}
}
