package gitlab

import (
	"fmt"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"

	"github.com/go-errors/errors"
	gogit "github.com/go-git/go-git/v5"
	"github.com/gobwas/glob"
	"github.com/xanzy/go-gitlab"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_GITLAB

type Source struct {
	name            string
	sourceId        sources.SourceID
	jobId           sources.JobID
	verify          bool
	authMethod      string
	user            string
	password        string
	token           string
	url             string
	repos           []string
	ignoreRepos     []string
	git             *git.Git
	scanOptions     *git.ScanOptions
	resumeInfoSlice []string
	resumeInfoMutex sync.Mutex
	sources.Progress
	jobPool *errgroup.Group
	sources.CommonSourceUnitUnmarshaller
}

// Ensure the Source satisfies the interfaces at compile time.
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)
var _ sources.Validator = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

func (s *Source) JobID() sources.JobID {
	return s.jobId
}

// Init returns an initialized Gitlab source.
func (s *Source) Init(_ context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)

	var conn sourcespb.GitLab
	err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.repos = conn.Repositories
	s.ignoreRepos = conn.IgnoreRepos
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

	err = git.CmdCheck()
	if err != nil {
		return err
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
						Link:       giturl.GenerateLink(repository, commit, file, line),
						Timestamp:  sanitizer.UTF8(timestamp),
						Line:       line,
					},
				},
			}
		})

	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	// Start client.
	apiClient, err := s.newClient()
	if err != nil {
		return errors.New(err)
	}

	gitlabReposScanned.WithLabelValues(s.name).Set(0)
	// Get repo within target.
	repos, errs := normalizeRepos(s.repos)
	for _, repoErr := range errs {
		ctx.Logger().Info("error normalizing repo", "error", repoErr)
	}

	// End early if we had errors getting specified repos but none were validated.
	if len(errs) > 0 && len(repos) == 0 {
		return errors.New("All specified repos had validation issues, ending scan")
	}

	// Get all repos if not specified.
	if len(repos) == 0 {
		ignoreRepo := buildIgnorer(s.ignoreRepos, func(err error, pattern string) {
			ctx.Logger().Error(err, "could not compile ignore repo glob", "glob", pattern)
		})
		gitlabRepos, err2, done := s.getReposFromGitlab(ctx, apiClient, ignoreRepo)
		if done {
			return err2
		}
		repos = gitlabRepos
	}

	s.repos = repos
	gitlabReposEnumerated.WithLabelValues(s.name).Set(float64(len(repos)))
	// We must sort the repos so we can resume later if necessary.
	slices.Sort(s.repos)

	return s.scanRepos(ctx, chunksChan)
}

func (s *Source) Validate(ctx context.Context) []error {
	// The client is only used to query Gitlab for a repo list - it's not used to actually clone anything. Thus, we
	// don't use it if there is a list of explicitly configured repos. However, constructing it validates that the
	// configured authentication method is sensible, so we'll do it here.
	apiClient, err := s.newClient()
	if err != nil {
		return []error{err}
	}

	_, _, err = apiClient.Users.CurrentUser()
	if err != nil {
		msg := fmt.Sprintf("gitlab authentication failed using method %v", s.authMethod)
		return []error{errors.WrapPrefix(err, msg, 0)}
	}

	explicitlyConfiguredRepos, errs := normalizeRepos(s.repos)

	if len(explicitlyConfiguredRepos) > 0 {
		user := s.user
		if user == "" {
			user = "placeholder"
		}

		// We only check reachability for explicitly configured repositories. The purpose of source validation is to
		// help users validate their configuration files, and Gitlab telling us about repositories that it won't let us
		// access isn't a local configuration issue.
		for _, r := range explicitlyConfiguredRepos {
			if err := git.PingRepoUsingToken(ctx, s.token, r, user); err != nil {
				msg := fmt.Sprintf("could not reach git repository %q", r)
				err = errors.WrapPrefix(err, msg, 0)
				errs = append(errs, err)
			}
		}

		if len(s.ignoreRepos) > 0 {
			errs = append(errs, fmt.Errorf("both repositories and ignore patterns were explicitly configured; ignore patterns will not be used"))
		}
	}

	if len(explicitlyConfiguredRepos) > 0 || len(errs) > 0 {
		return errs
	}

	ignoreProject := buildIgnorer(s.ignoreRepos, func(err error, pattern string) {
		msg := fmt.Sprintf("could not compile ignore repo pattern %q", pattern)
		errs = append(errs, errors.WrapPrefix(err, msg, 0))
	})

	projects, err := s.getAllProjects(ctx, apiClient)
	if err != nil {
		errs = append(errs, err)
		return errs
	}

	for _, p := range projects {
		if !ignoreProject(p.PathWithNamespace) {
			return errs
		}
	}

	return append(errs, fmt.Errorf("ignore patterns excluded all projects"))
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

func (s *Source) getAllProjects(ctx context.Context, apiClient *gitlab.Client) ([]*gitlab.Project, error) {
	// Projects without repo will get user projects, groups projects, and subgroup projects.
	user, _, err := apiClient.Users.CurrentUser()
	if err != nil {
		return nil, fmt.Errorf("unable to authenticate using %s, %w", s.authMethod, err)
	}

	uniqueProjects := make(map[int]*gitlab.Project)
	var (
		projects              []*gitlab.Project
		projectsWithNamespace []string
	)

	// Used to filter out duplicate projects.
	processProjects := func(projList []*gitlab.Project) {
		for _, proj := range projList {
			if _, exists := uniqueProjects[proj.ID]; !exists {
				uniqueProjects[proj.ID] = proj
				projects = append(projects, proj)
				projectsWithNamespace = append(projectsWithNamespace, proj.NameWithNamespace)
			}
		}
	}

	const (
		orderBy         = "last_activity_at"
		paginationLimit = 100 // Default is 20, max is 100.
	)
	listOpts := gitlab.ListOptions{PerPage: paginationLimit}

	projectQueryOptions := &gitlab.ListProjectsOptions{OrderBy: gitlab.Ptr(orderBy), ListOptions: listOpts}
	for {
		userProjects, res, err := apiClient.Projects.ListUserProjects(user.ID, projectQueryOptions)
		if err != nil {
			return nil, fmt.Errorf("received error on listing user projects: %w", err)
		}
		processProjects(userProjects)
		projectQueryOptions.Page = res.NextPage
		if res.NextPage == 0 {
			break
		}
	}

	listGroupsOptions := gitlab.ListGroupsOptions{
		ListOptions:  listOpts,
		AllAvailable: gitlab.Ptr(false), // This actually grabs public groups on public GitLab if set to true.
		TopLevelOnly: gitlab.Ptr(false),
		Owned:        gitlab.Ptr(false),
	}
	const cloudBaseURL = "https://gitlab.com/"
	if s.url != cloudBaseURL {
		listGroupsOptions.AllAvailable = gitlab.Ptr(true)
	}

	var groups []*gitlab.Group
	for {
		groupList, res, err := apiClient.Groups.ListGroups(&listGroupsOptions)
		if err != nil {
			return nil, fmt.Errorf("received error on listing groups, you probably don't have permissions to do that: %w", err)
		}
		groups = append(groups, groupList...)
		listGroupsOptions.Page = res.NextPage
		if res.NextPage == 0 {
			break
		}
	}

	for _, group := range groups {
		listGroupProjectOptions := &gitlab.ListGroupProjectsOptions{
			ListOptions:      listOpts,
			OrderBy:          gitlab.Ptr(orderBy),
			IncludeSubGroups: gitlab.Ptr(true),
		}
		for {
			grpPrjs, res, err := apiClient.Groups.ListGroupProjects(group.ID, listGroupProjectOptions)
			if err != nil {
				ctx.Logger().Info("received error on listing group projects, you probably don't have permissions to do that",
					"group", group.FullPath,
					"error", err,
				)
				break
			}
			processProjects(grpPrjs)
			listGroupProjectOptions.Page = res.NextPage
			if res.NextPage == 0 {
				break
			}
		}
	}

	ctx.Logger().Info("Enumerated GitLab projects", "count", len(projects))
	ctx.Logger().V(2).Info("Enumerated GitLab projects", "projects", projectsWithNamespace)

	return projects, nil
}

func (s *Source) getReposFromGitlab(ctx context.Context, apiClient *gitlab.Client, ignoreRepo func(repo string) bool) ([]string, error, bool) {
	projects, err := s.getAllProjects(ctx, apiClient)
	if err != nil {
		return nil, fmt.Errorf("error getting all projects: %v", err), true
	}

	// Turn projects into URLs for Git cloner.
	var repos []string
	for _, prj := range projects {
		if ignoreRepo(prj.PathWithNamespace) {
			continue
		}

		// Ensure the urls are valid before adding them to the repo list.
		_, err := url.Parse(prj.HTTPURLToRepo)
		if err != nil {
			fmt.Printf("could not parse url given by project: %s", prj.HTTPURLToRepo)
		}
		repos = append(repos, prj.HTTPURLToRepo)
	}
	if len(repos) == 0 {
		return nil, errors.Errorf("unable to discover any repos"), true
	}

	return repos, nil, false
}

func (s *Source) scanRepos(ctx context.Context, chunksChan chan *sources.Chunk) error {
	// If there is resume information available, limit this scan to only the repos that still need scanning.
	reposToScan, progressIndexOffset := sources.FilterReposToResume(s.repos, s.GetProgress().EncodedResumeInfo)
	s.repos = reposToScan
	scanErrs := sources.NewScanErrors()

	for i, repo := range s.repos {
		i, repoURL := i, repo
		s.jobPool.Go(func() error {
			logger := ctx.Logger().WithValues("repo", repoURL)
			if common.IsDone(ctx) {
				// We are returning nil instead of the scanErrors slice here because
				// we don't want to mark this scan as errored if we cancelled it.
				logger.V(2).Info("Skipping repo because context was cancelled")
				return nil
			}

			if len(repoURL) == 0 {
				logger.V(2).Info("Skipping empty repo")
				return nil
			}

			s.setProgressCompleteWithRepo(i, progressIndexOffset, repoURL)
			// Ensure the repo is removed from the resume info after being scanned.
			defer func(s *Source) {
				s.resumeInfoMutex.Lock()
				defer s.resumeInfoMutex.Unlock()
				s.resumeInfoSlice = sources.RemoveRepoFromResumeInfo(s.resumeInfoSlice, repoURL)
			}(s)

			var path string
			var repo *gogit.Repository
			var err error
			if s.authMethod == "UNAUTHENTICATED" {
				path, repo, err = git.CloneRepoUsingUnauthenticated(ctx, repoURL)
			} else {
				// If a username is not provided we need to use a default one in order to clone a private repo.
				// Not setting "placeholder" as s.user on purpose in case any downstream services rely on a "" value for s.user.
				user := s.user
				if user == "" {
					user = "placeholder"
				}
				path, repo, err = git.CloneRepoUsingToken(ctx, s.token, repoURL, user)
			}
			defer os.RemoveAll(path)
			if err != nil {
				scanErrs.Add(err)
				return nil
			}

			logger.V(2).Info(fmt.Sprintf("Starting to scan repo %d/%d", i+1, len(s.repos)))
			if err = s.git.ScanRepo(ctx, repo, path, s.scanOptions, sources.ChanReporter{Ch: chunksChan}); err != nil {
				scanErrs.Add(err)
				return nil
			}
			gitlabReposScanned.WithLabelValues(s.name).Inc()

			logger.V(2).Info(fmt.Sprintf("Completed scanning repo %d/%d", i+1, len(s.repos)))
			return nil
		})
	}

	_ = s.jobPool.Wait()
	if scanErrs.Count() > 0 {
		ctx.Logger().V(2).Info("encountered errors while scanning", "count", scanErrs.Count(), "errors", scanErrs)
	}
	s.SetProgressComplete(len(s.repos), len(s.repos), "Completed Gitlab scan", "")

	return nil
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

	// Add the offset to both the index and the repos to give the proper place and proper repo count.
	s.SetProgressComplete(index+offset, len(s.repos)+offset, fmt.Sprintf("Repo: %s", repoURL), encodedResumeInfo)
}

func (s *Source) WithScanOptions(scanOptions *git.ScanOptions) {
	s.scanOptions = scanOptions
}

func buildIgnorer(patterns []string, onCompileErr func(err error, pattern string)) func(repo string) bool {
	var globs []glob.Glob

	for _, pattern := range patterns {
		g, err := glob.Compile(pattern)
		if err != nil {
			onCompileErr(err, pattern)
			continue
		}
		globs = append(globs, g)
	}

	f := func(repo string) bool {
		for _, g := range globs {
			if g.Match(repo) {
				return true
			}
		}
		return false
	}

	return f
}

func normalizeRepos(repos []string) ([]string, []error) {
	var validRepos []string
	var errs []error
	for _, prj := range repos {
		repo, err := giturl.NormalizeGitlabRepo(prj)
		if err != nil {
			errs = append(errs, errors.WrapPrefix(err, fmt.Sprintf("unable to normalize gitlab repo url %s", prj), 0))
			continue
		}

		validRepos = append(validRepos, repo)
	}
	return validRepos, errs
}
