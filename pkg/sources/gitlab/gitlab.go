package gitlab

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/go-errors/errors"
	gogit "github.com/go-git/go-git/v5"
	log "github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
	"github.com/xanzy/go-gitlab"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type Source struct {
	name       string
	sourceId   int64
	jobId      int64
	verify     bool
	authMethod string
	user       string
	password   string
	token      string
	url        string
	repos      []string
	git        *git.Git
	aCtx       context.Context
	sources.Progress
	jobSem *semaphore.Weighted
}

// Ensure the Source satisfies the interface at compile time.
var _ sources.Source = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_GITLAB
}

func (s *Source) SourceID() int64 {
	return s.sourceId
}

func (s *Source) JobID() int64 {
	return s.jobId
}

// Init returns an initialized Gitlab source.
func (s *Source) Init(aCtx context.Context, name string, jobId, sourceId int64, verify bool, connection *anypb.Any, concurrency int) error {

	s.aCtx = aCtx
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.jobSem = semaphore.NewWeighted(int64(concurrency))

	var conn sourcespb.GitLab
	err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.repos = conn.Repositories
	s.url = conn.Endpoint
	if conn.Endpoint != "" && !strings.HasSuffix(s.url, "/") {
		s.url = s.url + "/"
	}
	switch cred := conn.GetCredential().(type) {
	case *sourcespb.GitLab_Token:
		s.authMethod = "TOKEN"
		s.token = cred.Token
	case *sourcespb.GitLab_Oauth:
		s.authMethod = "OAUTH"
		s.token = cred.Oauth.RefreshToken
		// TODO: is it okay if there is no client id and secret? Might be an issue when marshalling config to proto
	case *sourcespb.GitLab_BasicAuth:
		s.authMethod = "BASIC_AUTH"
		s.user = cred.BasicAuth.Username
		s.password = cred.BasicAuth.Password
		// We may need the password as a token if the user is using an access_token with basic auth.
		s.token = cred.BasicAuth.Password
	default:
		return errors.Errorf("Invalid configuration given for source. Name: %s, Type: %s", name, s.Type())
	}

	if len(s.url) == 0 {
		// Assuming not custom gitlab url.
		s.url = "https://gitlab.com/"
	}

	s.git = git.NewGit(s.Type(), s.JobID(), s.SourceID(), s.name, s.verify, runtime.NumCPU(),
		func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Gitlab{
					Gitlab: &source_metadatapb.Gitlab{
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

func (s *Source) newClient() (*gitlab.Client, error) {
	// Initialize a new api instance.
	switch s.authMethod {
	case "OAUTH":
		apiClient, err := gitlab.NewOAuthClient(s.token, gitlab.WithBaseURL(s.url))
		if err != nil {
			return nil, fmt.Errorf("could not create Gitlab OAUTH client for %s. Error: %v", s.url, err)
		}
		return apiClient, nil

	case "BASIC_AUTH":
		apiClient, err := gitlab.NewBasicAuthClient(s.user, s.password, gitlab.WithBaseURL(s.url))
		if err != nil {
			return nil, fmt.Errorf("could not create Gitlab BASICAUTH client for %s. Error: %v", s.url, err)
		}
		// If the user is using an access_token rather than a username/password, then basic auth
		// will not work. In this case, we test to see if basic auth would work, and if it does not,
		// we proceed with an OAuth client using the access_token (s.password) as the token.
		// At this point, s.token is already set to s.password
		if s.basicAuthSuccessful(apiClient) {
			return apiClient, nil
		}
		fallthrough
	case "TOKEN":
		apiClient, err := gitlab.NewOAuthClient(s.token, gitlab.WithBaseURL(s.url))
		if err != nil {
			return nil, fmt.Errorf("could not create Gitlab TOKEN client for %s. Error: %v", s.url, err)
		}
		return apiClient, nil

	default:
		return nil, errors.New("Could not determine authMethod specified for GitLab")
	}
}

func (s *Source) getAllProjects(apiClient *gitlab.Client) ([]*gitlab.Project, error) {
	// Projects without repo will get user projects, groups projects, and subgroup projects.
	user, _, err := apiClient.Users.CurrentUser()

	if err != nil {
		msg := fmt.Sprintf("unable to authenticate using: %s", s.authMethod)
		return nil, errors.WrapPrefix(err, msg, 0)
	}

	projects := map[int]*gitlab.Project{}

	projectQueryOptions := &gitlab.ListProjectsOptions{
		OrderBy: gitlab.String("last_activity_at"),
	}
	for {
		userProjects, res, err := apiClient.Projects.ListUserProjects(user.ID, projectQueryOptions)
		if err != nil {
			return nil, errors.Errorf("received error on listing user projects: %s\n", err)
		}
		for _, prj := range userProjects {
			projects[prj.ID] = prj
		}
		projectQueryOptions.Page = res.NextPage
		if res.NextPage == 0 {
			break
		}
	}

	var groups []*gitlab.Group

	listGroupsOptions := gitlab.ListGroupsOptions{
		AllAvailable: gitlab.Bool(false), // This actually grabs public groups on public GitLab if set to true.
		TopLevelOnly: gitlab.Bool(false),
		Owned:        gitlab.Bool(false),
	}
	if s.url != "https://gitlab.com/" {
		listGroupsOptions.AllAvailable = gitlab.Bool(true)
	}
	for {
		groupList, res, err := apiClient.Groups.ListGroups(&listGroupsOptions)
		if err != nil {
			return nil, errors.Errorf("received error on listing groups, you probably don't have permissions to do that: %s\n", err)
		}
		groups = append(groups, groupList...)
		listGroupsOptions.Page = res.NextPage
		if res.NextPage == 0 {
			break
		}
	}

	for _, group := range groups {
		listGroupProjectOptions := &gitlab.ListGroupProjectsOptions{
			OrderBy:          gitlab.String("last_activity_at"),
			IncludeSubGroups: gitlab.Bool(true),
		}
		for {
			grpPrjs, res, err := apiClient.Groups.ListGroupProjects(group.ID, listGroupProjectOptions)
			if err != nil {
				log.WithError(err).WithField("group", group.FullPath).Warn("received error on listing group projects, you probably don't have permissions to do that")
				break
			}
			for _, prj := range grpPrjs {
				projects[prj.ID] = prj
			}
			listGroupProjectOptions.Page = res.NextPage
			if res.NextPage == 0 {
				break
			}
		}
	}
	var projectNamesWithNamespace []string
	for _, project := range projects {
		projectNamesWithNamespace = append(projectNamesWithNamespace, project.NameWithNamespace)
	}
	log.WithField("projects", strings.Join(projectNamesWithNamespace, ", ")).Debugf("Enumerated %d GitLab projects", len(projects))

	var projectList []*gitlab.Project
	for _, project := range projects {
		projectList = append(projectList, project)
	}
	return projectList, nil
}

func (s *Source) getRepos() ([]*url.URL, []error) {
	var validRepos []*url.URL
	var errs []error
	if len(s.repos) > 0 {
		for _, prj := range s.repos {
			repo, err := giturl.NormalizeGitlabRepo(prj)
			if err != nil {
				errs = append(errs, errors.WrapPrefix(err, fmt.Sprintf("unable to normalize gitlab repo url %s", prj), 0))
				continue
			}

			// The repo normalization has already successfully parsed the URL at this point, so we can ignore the error.
			u, _ := url.ParseRequestURI(repo)
			validRepos = append(validRepos, u)
		}
		return validRepos, errs
	}
	return nil, nil

}

func (s *Source) scanRepos(ctx context.Context, chunksChan chan *sources.Chunk, repos []*url.URL) []error {
	wg := sync.WaitGroup{}
	var errs []error
	var errsMut sync.Mutex

	for i, u := range repos {
		if common.IsDone(ctx) {
			// We are returning nil instead of the scanErrors slice here because
			// we don't want to mark this scan as errored if we cancelled it.
			return nil
		}
		if err := s.jobSem.Acquire(ctx, 1); err != nil {
			log.WithError(err).Debug("could not acquire semaphore")
			continue
		}
		wg.Add(1)
		go func(ctx context.Context, repoURL *url.URL, i int) {
			defer s.jobSem.Release(1)
			defer wg.Done()
			if len(repoURL.String()) == 0 {
				return
			}
			s.SetProgressComplete(i, len(repos), fmt.Sprintf("Repo: %s", repoURL), "")

			var path string
			var repo *gogit.Repository
			var err error
			if s.authMethod == "UNAUTHENTICATED" {
				path, repo, err = git.CloneRepoUsingUnauthenticated(repoURL.String())
			} else {
				// If a username is not provided we need to use a default one in order to clone a private repo.
				// Not setting "placeholder" as s.user on purpose in case any downstream services rely on a "" value for s.user.
				user := s.user
				if user == "" {
					user = "placeholder"
				}
				path, repo, err = git.CloneRepoUsingToken(s.token, repoURL.String(), user)
			}
			defer os.RemoveAll(path)
			if err != nil {
				errsMut.Lock()
				errs = append(errs, err)
				errsMut.Unlock()
				return
			}
			log.Debugf("Starting to scan repo %d/%d: %s", i+1, len(repos), repoURL.String())
			err = s.git.ScanRepo(ctx, repo, path, git.NewScanOptions(), chunksChan)
			if err != nil {
				errsMut.Lock()
				errs = append(errs, err)
				errsMut.Unlock()
				return
			}
			log.Debugf("Completed scanning repo %d/%d: %s", i+1, len(repos), repoURL.String())
		}(ctx, u, i)
	}
	wg.Wait()

	return errs
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	// Start client.
	apiClient, err := s.newClient()
	if err != nil {
		return errors.New(err)
	}
	// Get repo within target.
	repos, errs := s.getRepos()
	for _, repoErr := range errs {
		log.WithError(repoErr).Warn("error getting repo")
	}

	// End early if we had errors getting specified repos but none were validated.
	if len(errs) > 0 && len(repos) == 0 {
		return errors.New("All specified repos had validation issues, ending scan")
	}

	// Get all repos if not specified.
	if repos == nil {
		projects, err := s.getAllProjects(apiClient)
		if err != nil {
			return errors.New(err)
		}
		// Turn projects into URLs for Git cloner.
		for _, prj := range projects {
			u, err := url.Parse(prj.HTTPURLToRepo)
			if err != nil {
				fmt.Printf("could not parse url given by project: %s", prj.HTTPURLToRepo)
			}
			repos = append(repos, u)
		}
		if repos == nil {
			return errors.Errorf("unable to discover any repos")
		}
	}
	errs = s.scanRepos(ctx, chunksChan, repos)
	for _, err := range errs {
		log.WithError(err).WithFields(
			log.Fields{
				"source_name": s.name,
				"source_type": s.Type(),
				"repos":       repos,
			},
		).Error("error scanning repo")
	}

	return nil
}

func (s *Source) basicAuthSuccessful(apiClient *gitlab.Client) bool {
	user, resp, err := apiClient.Users.CurrentUser()
	if err != nil {
		return false
	}
	if resp.StatusCode != 200 {
		return false
	}
	if user != nil {
		return true
	}
	return false
}
