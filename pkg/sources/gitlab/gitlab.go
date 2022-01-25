package gitlab

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"sync"

	"github.com/go-errors/errors"
	log "github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/pkg/common"
	"github.com/trufflesecurity/trufflehog/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/pkg/sources"
	"github.com/trufflesecurity/trufflehog/pkg/sources/git"
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

// Ensure the Source satisfies the interface at compile time
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
		errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.repos = conn.Repositories
	s.url = conn.Endpoint
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
	default:
		return errors.Errorf("Invalid configuration given for source. Name: %s, Type: %s", name, s.Type())
	}

	if len(s.url) == 0 {
		//assuming not custom gitlab url
		s.url = "https://gitlab.com/"
	}

	s.git = git.NewGit(s.Type(), s.JobID(), s.SourceID(), s.name, s.verify, runtime.NumCPU(),
		func(file, email, commit, repository string) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Gitlab{
					Gitlab: &source_metadatapb.Gitlab{
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

func (s *Source) newClient() (*gitlab.Client, error) {

	// initialize a new api instance
	switch s.authMethod {
	case "OAUTH":
		apiClient, err := gitlab.NewOAuthClient(s.token, gitlab.WithBaseURL(s.url))
		if err != nil {
			return nil, fmt.Errorf("could not authenticate to Gitlab instance %s via OAUTH. Error: %v", s.url, err)
		}
		return apiClient, nil
	case "BASIC_AUTH":
		apiClient, err := gitlab.NewBasicAuthClient(s.user, s.password, gitlab.WithBaseURL(s.url))
		if err != nil {
			return nil, fmt.Errorf("could not authenticate to Gitlab instance %s via BASICAUTH. Error: %v", s.url, err)
		}
		return apiClient, nil

	case "TOKEN":
		apiClient, err := gitlab.NewOAuthClient(s.token, gitlab.WithBaseURL(s.url))
		if err != nil {
			return nil, fmt.Errorf("could not authenticate to Gitlab instance %s via TOKEN Auth. Error: %v", s.url, err)
		}
		return apiClient, nil

	default:
		return nil, errors.New("Could not determine authMethod specified for GitLab")
	}

}

func (s *Source) getAllProjects(apiClient *gitlab.Client) ([]*gitlab.Project, error) {
	// projects without repo will get user projects, groups projects, and subgroup projects.
	user, _, err := apiClient.Users.CurrentUser()
	//TODO what happens if the user is anonymous
	if err != nil {
		return nil, errors.Errorf("unable to authenticate using: %s", s.authMethod)
	}

	var projects []*gitlab.Project

	// TODO: enumerate all usewr projects
	projectQueryOptions := &gitlab.ListProjectsOptions{
		OrderBy: gitlab.String("last_activity_at"),
	}
	for {
		userProjects, res, err := apiClient.Projects.ListUserProjects(user.ID, projectQueryOptions)
		if err != nil {
			return nil, errors.Errorf("received error on listing projects: %s\n", err)
		}
		projects = append(projects, userProjects...)
		projectQueryOptions.Page = res.NextPage
		if res.NextPage == 0 {
			break
		}
	}

	var groups []*gitlab.Group

	listGroupsOptions := gitlab.ListGroupsOptions{
		AllAvailable: gitlab.Bool(false), // This actually grabs outside groups on public GitLab
		TopLevelOnly: gitlab.Bool(false),
		Owned:        gitlab.Bool(false),
	}
	if s.url != "https://gitlab.com/" {
		listGroupsOptions.AllAvailable = gitlab.Bool(true)
	}
	for {
		groupList, res, err := apiClient.Groups.ListGroups(&listGroupsOptions)
		if err != nil {
			return nil, errors.Errorf("received error on listing projects: %s\n", err)
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
			IncludeSubgroups: gitlab.Bool(true),
		}
		for {
			grpPrjs, res, err := apiClient.Groups.ListGroupProjects(group.ID, listGroupProjectOptions)
			if err != nil {
				return nil, errors.Errorf("received error on listing projects: %s\n", err)
			}
			projects = append(projects, grpPrjs...)
			listGroupProjectOptions.Page = res.NextPage
			if res.NextPage == 0 {
				break
			}
		}
	}
	log.WithField("projects", projects).Debugf("Enumerated %d GitLab projects", len(projects))
	return projects, nil
}

func (s *Source) getRepos(apiClient *gitlab.Client) ([]*url.URL, []error) {
	//is repo defined?
	var validRepos []*url.URL
	var errs []error
	if len(s.repos) > 0 {
		for _, prj := range s.repos {
			repo, err := giturl.NormalizeGitlabRepo(prj)
			if err != nil {
				errs = append(errs, errors.WrapPrefix(err, fmt.Sprintf("unable to normalize gitlab repo url %s", prj), 0))
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
	errChan := make(chan error)
	wg := sync.WaitGroup{}
	if s.authMethod == "UNAUTHENTICATED" {
		for i, u := range repos {
			if common.IsDone(ctx) {
				// We are returning nil instead of the errors slice here because
				// we don't want to mark this scan as errored if we cancelled it.
				return nil
			}
			s.jobSem.Acquire(ctx, 1)
			wg.Add(1)
			go func(ctx context.Context, errCh chan error, repoURL *url.URL, i int) {
				defer s.jobSem.Release(1)
				defer wg.Done()
				if len(repoURL.String()) == 0 {
					return
				}
				s.SetProgressComplete(i, len(repos), fmt.Sprintf("Repo: %s", repoURL))

				path, repo, err := git.CloneRepoUsingUnauthenticated(repoURL.String())
				defer os.RemoveAll(path)
				if err != nil {
					errCh <- err
					return
				}
				err = s.git.ScanRepo(ctx, repo, git.NewScanOptions(), chunksChan)
				if err != nil {
					errCh <- err
					return
				}
			}(ctx, errChan, u, i)
		}

	} else {
		for i, u := range repos {
			if common.IsDone(ctx) {
				// We are returning nil instead of the errors slice here because
				// we don't want to mark this scan as errored if we cancelled it.
				return nil
			}
			s.jobSem.Acquire(ctx, 1)
			wg.Add(1)
			go func(ctx context.Context, errCh chan error, repoURL *url.URL, i int) {
				defer s.jobSem.Release(1)
				defer wg.Done()
				if len(repoURL.String()) == 0 {
					return
				}
				s.SetProgressComplete(i, len(repos), fmt.Sprintf("Repo: %s", repoURL))

				path, repo, err := git.CloneRepoUsingToken(s.token, repoURL.String(), s.user)
				defer os.RemoveAll(path)
				if err != nil {
					errCh <- err
					return
				}
				err = s.git.ScanRepo(ctx, repo, git.NewScanOptions(), chunksChan)
				if err != nil {
					errCh <- err
					return
				}
			}(ctx, errChan, u, i)
		}
	}

	wg.Wait()
	close(errChan)

	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	return errors
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	// start client
	apiClient, err := s.newClient()
	if err != nil {
		return errors.New(err)
	}
	// get repo within target
	repos, errs := s.getRepos(apiClient)
	for _, repoErr := range errs {
		log.WithError(repoErr).Warn("error getting repo")
	}
	// get all repos if not specified
	if repos == nil {
		projects, err := s.getAllProjects(apiClient)
		if err != nil {
			return errors.New(err)
		}
		// turn projects into URLs for Git cloner
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
