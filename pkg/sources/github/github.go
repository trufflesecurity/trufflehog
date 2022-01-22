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
	"time"

	"github.com/bradleyfalzon/ghinstallation"
	"github.com/go-errors/errors"
	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v41/github"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/pkg/pb/sourcespb"

	"github.com/trufflesecurity/trufflehog/pkg/common"
	"github.com/trufflesecurity/trufflehog/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/pkg/sources"
	"github.com/trufflesecurity/trufflehog/pkg/sources/git"
)

type Source struct {
	name       string
	sourceId   int64
	jobId      int64
	verify     bool
	repos      []string
	orgs       []string
	members    []string
	git        *git.Git
	httpClient *http.Client
	aCtx       context.Context
	sources.Progress
	log   *log.Entry
	token string
	conn  *sourcespb.GitHub
}

// Ensure the Source satisfies the interface at compile time
var _ sources.Source = (*Source)(nil)
var endsWithGithub = regexp.MustCompile(`github.com/?$`)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_GITHUB
}

func (s *Source) SourceID() int64 {
	return s.sourceId
}

func (s *Source) JobID() int64 {
	return s.jobId
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
func (s *Source) Init(aCtx context.Context, name string, jobId, sourceId int64, verify bool, connection *anypb.Any, concurrency int) error {
	s.log = log.WithField("source", s.Type()).WithField("name", name)

	s.aCtx = aCtx
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify

	s.httpClient = common.SaneHttpClient()

	var conn sourcespb.GitHub
	err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}
	s.conn = &conn

	s.git = git.NewGit(s.Type(), s.JobID(), s.SourceID(), s.name, s.verify, runtime.NumCPU(),
		func(file, email, commit, repository string) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Github{
					Github: &source_metadatapb.Github{
						Commit:     sanitizer.UTF8(commit),
						File:       sanitizer.UTF8(file),
						Email:      sanitizer.UTF8(email),
						Repository: sanitizer.UTF8(repository),
						Link:       git.GenerateLink(repository, commit, file),
					},
				},
			}
		})

	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	apiEndpoint := s.conn.Endpoint
	if len(s.conn.Endpoint) == 0 || endsWithGithub.MatchString(apiEndpoint) {
		apiEndpoint = "https://api.github.com"
	}

	var installationClient *github.Client
	s.repos = s.conn.Repositories
	s.orgs = s.conn.Organizations

	switch cred := s.conn.GetCredential().(type) {
	case *sourcespb.GitHub_Unauthenticated:
		apiClient := github.NewClient(s.httpClient)
		if len(s.orgs) > 30 {
			log.Warn("You may experience rate limiting when using the unauthenticated GitHub api. Consider using an authenticated scan instead.")
		}

		if len(s.repos) > 0 {
			for i, repo := range s.repos {
				if !strings.HasSuffix(repo, ".git") {
					if repo, err := giturl.NormalizeGithubRepo(repo); err != nil {
						// This wasn't formatted as expected, let the user know why that might be.
						log.WithError(err).Warnf("Repo not in expected format, attempting to paginate repos instead.")
					} else {
						s.repos[i] = repo
					}
					s.paginateRepos(ctx, apiClient, repo)
				}
			}
		}

		if len(s.orgs) > 0 {
			for _, org := range s.orgs {
				s.paginateRepos(ctx, apiClient, org)
			}
		}
	case *sourcespb.GitHub_Token:
		// needed for clones
		s.token = cred.Token

		// needed to list repos
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: cred.Token},
		)
		tc := oauth2.NewClient(context.TODO(), ts)

		var apiClient *github.Client
		var err error
		// If we're using public github, make a regular client.
		// Otherwise make an enterprise client
		if apiEndpoint == "https://api.github.com" {
			apiClient = github.NewClient(tc)
		} else {
			apiClient, err = github.NewEnterpriseClient(apiEndpoint, apiEndpoint, tc)
			if err != nil {
				return errors.New(err)
			}
		}

		// TODO: this should support scanning users too

		specificScope := false

		if len(s.repos) > 0 {
			specificScope = true
			for i, repo := range s.repos {
				if !strings.HasSuffix(repo, ".git") {
					if repo, err := giturl.NormalizeGithubRepo(repo); err != nil {
						// This wasn't formatted as expected, let the user know why that might be.
						log.WithError(err).Warnf("Repo not in expected format, attempting to paginate repos instead.")
					} else {
						s.repos[i] = repo
					}
					s.paginateRepos(ctx, apiClient, repo)
				}
			}
		}

		if len(s.orgs) > 0 {
			specificScope = true
			for _, org := range s.orgs {
				if !strings.HasSuffix(org, ".git") {
					s.paginateRepos(ctx, apiClient, org)
				}
			}
		}

		user, _, err := apiClient.Users.Get(context.TODO(), "")
		if err != nil {
			return errors.New(err)
		}
		// TODO: this should enumerate an organizations gists too...
		s.paginateGists(ctx, user.GetLogin(), chunksChan)

		if !specificScope {
			s.paginateRepos(ctx, apiClient, user.GetLogin())
			// Scan for orgs is default with a token. GitHub App enumerates the repositories
			// that were assigned to it in GitHub App settings.
			s.paginateOrgs(ctx, apiClient, *user.Name)
		}
	case *sourcespb.GitHub_GithubApp:
		installationID, err := strconv.ParseInt(cred.GithubApp.InstallationId, 10, 64)
		if err != nil {
			return errors.New(err)
		}

		appID, err := strconv.ParseInt(cred.GithubApp.AppId, 10, 64)
		if err != nil {
			return errors.New(err)
		}

		// This client is used for most APIs
		itr, err := ghinstallation.New(
			common.SaneHttpClient().Transport,
			appID,
			installationID,
			[]byte(cred.GithubApp.PrivateKey))
		if err != nil {
			return errors.New(err)
		}
		itr.BaseURL = apiEndpoint
		apiClient, err := github.NewEnterpriseClient(apiEndpoint, apiEndpoint, &http.Client{Transport: itr})
		if err != nil {
			return errors.New(err)
		}

		// This client is required to create installation tokens for cloning.. Otherwise the required JWT is not in the
		// request for the token :/
		appItr, err := ghinstallation.NewAppsTransport(
			common.SaneHttpClient().Transport,
			appID,
			[]byte(cred.GithubApp.PrivateKey))
		if err != nil {
			return errors.New(err)
		}
		appItr.BaseURL = apiEndpoint
		installationClient, err = github.NewEnterpriseClient(apiEndpoint, apiEndpoint, &http.Client{Transport: appItr})
		if err != nil {
			return errors.New(err)
		}

		err = s.paginateApp(ctx, apiClient)
		if err != nil {
			return err
		}

		//check if we need to find user repos
		if s.conn.ScanUsers {
			err := s.paginateMembers(ctx, installationClient, apiClient)
			if err != nil {
				return err
			}
			log.Infof("Scanning repos from %v organization members.", len(s.members))
			for _, member := range s.members {
				//all org member's gists
				s.paginateGists(ctx, member, chunksChan)
				s.paginateRepos(ctx, apiClient, member)
			}

		}
	default:
		return errors.Errorf("Invalid configuration given for source. Name: %s, Type: %s", s.name, s.Type())
	}

	if _, ok := os.LookupEnv("DO_NOT_RANDOMIZE"); !ok {
		//Randomize channel scan order on each scan
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(s.repos), func(i, j int) { s.repos[i], s.repos[j] = s.repos[j], s.repos[i] })
	}

	log.Infof("Found %v total repos to scan", len(s.repos))
	for i, repoURL := range s.repos {
		s.SetProgressComplete(i, len(s.repos), fmt.Sprintf("Repo: %s", repoURL))

		if !strings.HasSuffix(repoURL, ".git") {
			continue
		}
		if strings.Contains(repoURL, "DefinitelyTyped") {
			continue
		}
		s.log.WithField("repo", repoURL).Debug("attempting to clone repo")
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
				return err
			}
			path, repo, err = git.CloneRepoUsingToken(token, repoURL, "clone")
		}

		defer os.RemoveAll(path)
		if err != nil {
			log.WithError(err).Warnf("unable to clone repo, continuing")
			continue
		}
		err = s.git.ScanRepo(ctx, repo, git.NewScanOptions(), chunksChan)
		if err != nil {
			log.WithError(err).Warnf("unable to scan repo")
		}

	}

	return nil
}

// handleRateLimit returns true if a rate limit was handled
//unauthed github has a rate limit of 60 requests per hour. This will likely only be exhausted if many users/orgs are scanned without auth
func handleRateLimit(err error) bool {
	limit, ok := err.(*github.RateLimitError)
	if !ok {
		return false
	}
	log.WithField("retry-after", limit.Message).Debug("handling rate limit (5 minutes retry)")
	time.Sleep(time.Minute * 5)
	return true
}

func (s *Source) paginateReposByOrg(ctx context.Context, apiClient *github.Client, org string) {
	opts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}
	for {
		someRepos, res, err := apiClient.Repositories.ListByOrg(ctx, org, opts)
		if err == nil {
			defer res.Body.Close()
		}
		if handled := handleRateLimit(err); handled {
			continue
		}
		if len(someRepos) == 0 || err != nil {
			break
		}
		for _, r := range someRepos {
			s.repos = append(s.repos, r.GetCloneURL())
		}
		if res.NextPage == 0 {
			break
		}
		opts.Page = res.NextPage
	}
}

func (s *Source) paginateRepos(ctx context.Context, apiClient *github.Client, user string) {
	opts := &github.RepositoryListOptions{
		// Visibility: "all",
		ListOptions: github.ListOptions{
			PerPage: 50,
		},
	}
	for {
		someRepos, res, err := apiClient.Repositories.List(ctx, user, opts)
		if err == nil {
			defer res.Body.Close()
		}
		if handled := handleRateLimit(err); handled {
			continue
		}
		if err != nil {
			break
		}
		for _, r := range someRepos {
			s.repos = append(s.repos, r.GetCloneURL())
		}
		if res.NextPage == 0 {
			break
		}
		opts.Page = res.NextPage
	}
}

func (s *Source) paginateGists(ctx context.Context, user string, chunksChan chan *sources.Chunk) {
	apiClient := github.NewClient(s.httpClient)
	gists, _, err := apiClient.Gists.List(ctx, user, &github.GistListOptions{})
	if err != nil {
		log.WithError(err).Warnf("Could not get gists for user %s", user)
		return
	}
	for _, gist := range gists {
		path, repo, err := git.CloneRepoUsingUnauthenticated(*gist.GitPullURL)
		defer os.RemoveAll(path)
		if err != nil {
			log.WithError(err).Warnf("Could not get gist %s from user %s", *gist.HTMLURL, user)
			continue
		}
		s.log.WithField("repo", *gist.HTMLURL).Debugf("attempting to clone gist from user %s", user)

		scanCtx := context.Background()
		err = s.git.ScanRepo(scanCtx, repo, git.NewScanOptions(), chunksChan)
		if err != nil {
			log.WithError(err).Warnf("Could not scan after clone: %s", *gist.HTMLURL)
			continue
		}

	}

}

func (s *Source) paginateMembers(ctx context.Context, installationClient *github.Client, apiClient *github.Client) error {

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
			if handled := handleRateLimit(err); handled {
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
				s.members = append(s.members, *usr)
			}
			if res.NextPage == 0 {
				break
			}
			opts.Page = res.NextPage
		}

	}

	return nil
}

func (s *Source) paginateApp(ctx context.Context, apiClient *github.Client) error {
	// Authenticated enumeration of repos
	opts := &github.ListOptions{
		PerPage: 100,
	}
	for {
		someRepos, res, err := apiClient.Apps.ListRepos(ctx, opts)
		if err == nil {
			defer res.Body.Close()
		}
		if handled := handleRateLimit(err); handled {
			continue
		}
		if err != nil {
			return errors.WrapPrefix(err, "unable to list repositories", 0)
		}
		for _, r := range someRepos.Repositories {
			s.repos = append(s.repos, r.GetCloneURL())
		}
		if res.NextPage == 0 {
			break
		}
		opts.Page = res.NextPage
	}
	return nil
}

func (s *Source) paginateOrgs(ctx context.Context, apiClient *github.Client, user string) {
	orgOpts := &github.ListOptions{}
	orgs, _, err := apiClient.Organizations.List(ctx, "", orgOpts)
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
		s.paginateReposByOrg(ctx, apiClient, name)
	}

}
