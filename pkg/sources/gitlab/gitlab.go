package gitlab

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"runtime"

	"github.com/go-errors/errors"
	gogit "github.com/go-git/go-git/v5"
	log "github.com/sirupsen/logrus"
	"github.com/xanzy/go-gitlab"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/pkg/pb/sourcespb"

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
	authMethod string
	user       string
	password   string
	token      string
	url        string
	repos      []string
	git        *git.Git
	aCtx       context.Context
	sources.Progress
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
	//when bool pointers are req'd
	//yes := true
	no := false
	projectQuery := &gitlab.ListProjectsOptions{}
	projects, _, err := apiClient.Projects.ListUserProjects(user.ID, projectQuery)
	if err != nil {
		return nil, errors.Errorf("received error on listing projects: %s\n", err)
	}
	groups, _, err := apiClient.Groups.ListGroups(&gitlab.ListGroupsOptions{AllAvailable: &no})
	if err != nil {
		return nil, errors.Errorf("received error on listing projects: %s\n", err)
	}
	for _, group := range groups {
		grpPrjs, _, err := apiClient.Groups.ListGroupProjects(group.ID, &gitlab.ListGroupProjectsOptions{})
		if err != nil {
			return nil, errors.Errorf("received error on listing projects: %s\n", err)
		}
		projects = append(projects, grpPrjs...)
		subgroups, _, err := apiClient.Groups.ListSubgroups(group.ID, &gitlab.ListSubgroupsOptions{AllAvailable: &no})
		if err != nil {
			log.Debugf("could not retrieve subgroups from %s", group.Name)
			continue
		}
		for _, subgroup := range subgroups {
			projects = append(projects, subgroup.Projects...)
		}
	}
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
	var errors []error
	if s.authMethod == "UNAUTHENTICATED" {
		for i, u := range repos {
			s.SetProgressComplete(i, len(repos), fmt.Sprintf("Repo: %s", u))

			if len(u.String()) == 0 {
				continue
			}
			path, repo, err := git.CloneRepoUsingUnauthenticated(u.String())
			defer os.RemoveAll(path)
			if err != nil {
				errors = append(errors, err)
				continue
			}
			err = s.git.ScanRepo(ctx, repo, &gogit.LogOptions{All: true}, nil, chunksChan)
			if err != nil {
				errors = append(errors, err)
				continue
			}

		}

	} else {
		for i, u := range repos {
			s.SetProgressComplete(i, len(repos), fmt.Sprintf("Repo: %s", u))

			if len(u.String()) == 0 {
				continue
			}
			path, repo, err := git.CloneRepoUsingToken(s.token, u.String(), s.user)
			defer os.RemoveAll(path)
			if err != nil {
				errors = append(errors, err)
				continue
			}
			err = s.git.ScanRepo(ctx, repo, &gogit.LogOptions{All: true}, nil, chunksChan)
			if err != nil {
				errors = append(errors, err)
				continue
			}

		}
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
