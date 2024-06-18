package huggingface

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"github.com/gobwas/glob"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/memory"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

const (
	SourceType        = sourcespb.SourceType_SOURCE_TYPE_HUGGINGFACE
	DatasetsRoute     = "datasets"
	SpacesRoute       = "spaces"
	ModelsAPIRoute    = "models"
	DiscussionsRoute  = "discussions"
	APIRoute          = "api"
	DATASET           = "dataset"
	MODEL             = "model"
	SPACE             = "space"
	defaultPagination = 100
)

type resourceType string

type Source struct {
	name string

	// Protects the user and token.
	userMu           sync.Mutex
	huggingfaceUser  string
	huggingfaceToken string

	sourceID   sources.SourceID
	jobID      sources.JobID
	verify     bool
	orgsCache  cache.Cache[string]
	usersCache cache.Cache[string]

	models   []string
	spaces   []string
	datasets []string

	filteredModelsCache   *filteredRepoCache
	filteredSpacesCache   *filteredRepoCache
	filteredDatasetsCache *filteredRepoCache

	repoInfoCache repoInfoCache

	git *git.Git

	scanOptMu   sync.Mutex // protects the scanOptions
	scanOptions *git.ScanOptions

	httpClient      *http.Client
	log             logr.Logger
	conn            *sourcespb.Huggingface
	jobPool         *errgroup.Group
	resumeInfoMutex sync.Mutex
	resumeInfoSlice []string
	//apiClient       *Client

	onlyModels         bool
	onlySpaces         bool
	onlyDatasets       bool
	includeDiscussions bool
	includePrs         bool

	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

// Ensure the Source satisfies the interfaces at compile time
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceID
}

func (s *Source) JobID() sources.JobID {
	return s.jobID
}

// filteredRepoCache is a wrapper around cache.Cache that filters out repos
// based on include and exclude globs.
type filteredRepoCache struct {
	cache.Cache[string]
	include, exclude []glob.Glob
}

func (s *Source) newFilteredRepoCache(c cache.Cache[string], include, exclude []string) *filteredRepoCache {
	includeGlobs := make([]glob.Glob, 0, len(include))
	excludeGlobs := make([]glob.Glob, 0, len(exclude))
	for _, ig := range include {
		g, err := glob.Compile(ig)
		if err != nil {
			s.log.V(1).Info("invalid include glob", "include_value", ig, "err", err)
			continue
		}
		includeGlobs = append(includeGlobs, g)
	}
	for _, eg := range exclude {
		g, err := glob.Compile(eg)
		if err != nil {
			s.log.V(1).Info("invalid exclude glob", "exclude_value", eg, "err", err)
			continue
		}
		excludeGlobs = append(excludeGlobs, g)
	}
	return &filteredRepoCache{Cache: c, include: includeGlobs, exclude: excludeGlobs}
}

// Set overrides the cache.Cache Set method to filter out repos based on
// include and exclude globs.
func (c *filteredRepoCache) Set(key, val string) {
	if c.ignoreRepo(key) {
		return
	}
	if !c.includeRepo(key) {
		return
	}
	c.Cache.Set(key, val)
}

func (c *filteredRepoCache) ignoreRepo(s string) bool {
	for _, g := range c.exclude {
		if g.Match(s) {
			return true
		}
	}
	return false
}

func (c *filteredRepoCache) includeRepo(s string) bool {
	if len(c.include) == 0 {
		return true
	}

	for _, g := range c.include {
		if g.Match(s) {
			return true
		}
	}
	return false
}

// Init returns an initialized HuggingFace source.
func (s *Source) Init(aCtx context.Context, name string, jobID sources.JobID, sourceID sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	err := git.CmdCheck()
	if err != nil {
		return err
	}

	s.log = aCtx.Logger()

	s.name = name
	s.sourceID = sourceID
	s.jobID = jobID
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)

	s.httpClient = &http.Client{}

	var conn sourcespb.Huggingface
	err = anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}
	s.conn = &conn

	// ToDo: Add in orgs enumerations
	s.orgsCache = memory.New[string]()
	for _, org := range s.conn.Organizations {
		s.orgsCache.Set(org, org)
	}

	// ToDo: Add in users enumerations
	s.usersCache = memory.New[string]()
	for _, user := range s.conn.Users {
		s.usersCache.Set(user, user)
	}

	s.filteredModelsCache = s.newFilteredRepoCache(memory.New[string](),
		append(s.conn.GetModels(), s.conn.GetIncludeModels()...),
		s.conn.GetIgnoreModels(),
	)

	s.filteredSpacesCache = s.newFilteredRepoCache(memory.New[string](),
		append(s.conn.GetSpaces(), s.conn.GetIncludeSpaces()...),
		s.conn.GetIgnoreSpaces(),
	)

	s.filteredDatasetsCache = s.newFilteredRepoCache(memory.New[string](),
		append(s.conn.GetDatasets(), s.conn.GetIncludeDatasets()...),
		s.conn.GetIgnoreDatasets(),
	)

	s.models = s.conn.Models
	for _, model := range s.models {
		url := fmt.Sprintf("https://huggingface.co/%s.git", model)
		s.filteredModelsCache.Set(model, url)
	}

	s.spaces = s.conn.Spaces
	for _, space := range s.spaces {
		url := fmt.Sprintf("https://huggingface.co/%s/%s.git", SpacesRoute, space)
		s.filteredSpacesCache.Set(space, url)
	}

	s.datasets = s.conn.Datasets
	for _, dataset := range s.datasets {
		url := fmt.Sprintf("https://huggingface.co/%s/%s.git", DatasetsRoute, dataset)
		s.filteredDatasetsCache.Set(dataset, url)
	}
	s.repoInfoCache = newRepoInfoCache()

	s.includeDiscussions = s.conn.IncludeDiscussions
	s.includePrs = s.conn.IncludePrs

	cfg := &git.Config{
		SourceName: s.name,
		JobID:      s.jobID,
		SourceID:   s.sourceID,
		SourceType: s.Type(),
		Verify:     s.verify,
		// SkipBinaries: conn.GetSkipBinaries(),
		// SkipArchives: conn.GetSkipArchives(),
		Concurrency: concurrency,
		SourceMetadataFunc: func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Huggingface{
					Huggingface: &source_metadatapb.Huggingface{
						Commit:       sanitizer.UTF8(commit),
						File:         sanitizer.UTF8(file),
						Email:        sanitizer.UTF8(email),
						Repository:   sanitizer.UTF8(repository),
						Link:         giturl.GenerateLink(repository, commit, file, line),
						Timestamp:    sanitizer.UTF8(timestamp),
						Line:         line,
						Visibility:   s.visibilityOf(aCtx, repository),
						ResourceType: s.getResourceType(aCtx, repository),
					},
				},
			}
		},
		//UseCustomContentWriter: s.useCustomContentWriter,
	}
	s.git = git.NewGit(cfg)

	s.huggingfaceToken = s.conn.GetToken()

	return nil
}

func (s *Source) getResourceType(ctx context.Context, repoURL string) string {
	repoInfo, ok := s.repoInfoCache.get(repoURL)
	if !ok {
		// This should never happen.
		err := fmt.Errorf("no repoInfo for URL: %s", repoURL)
		ctx.Logger().Error(err, "failed to get repository resource type")
		return ""
	}

	return string(repoInfo.resourceType)
}

func (s *Source) visibilityOf(ctx context.Context, repoURL string) source_metadatapb.Visibility {
	repoInfo, ok := s.repoInfoCache.get(repoURL)
	if !ok {
		// This should never happen.
		err := fmt.Errorf("no repoInfo for URL: %s", repoURL)
		ctx.Logger().Error(err, "failed to get repository visibility")
		return source_metadatapb.Visibility_unknown
	}

	return repoInfo.visibility
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, targets ...sources.ChunkingTarget) error {
	// If targets are provided, we're only scanning the data in those targets.
	// Otherwise, we're scanning all data.
	// This allows us to only scan the commit where a vulnerability was found.
	// if len(targets) > 0 {
	// 	return s.scanTargets(ctx, targets, chunksChan)
	// }

	// Reset consumption and rate limit metrics on each run.
	// githubNumRateLimitEncountered.WithLabelValues(s.name).Set(0)
	// githubSecondsSpentRateLimited.WithLabelValues(s.name).Set(0)
	// githubReposScanned.WithLabelValues(s.name).Set(0)

	installationClient, err := s.enumerate(ctx, s.conn.Endpoint)
	if err != nil {
		return err
	}

	return s.scan(ctx, installationClient, chunksChan)
}

func (s *Source) enumerate(ctx context.Context, apiEndpoint string) (*http.Client, error) {
	var (
		installationClient *http.Client
		//err                error
	)

	// Todo: add back in when do org nad user enum
	// switch cred := s.conn.GetCredential().(type) {
	// case *sourcespb.HuggingFace_Unauthenticated:
	// 	s.enumerateUnauthenticated(ctx, apiEndpoint)
	// case *sourcespb.HuggingFace_Token:
	// 	if err = s.enumerateWithToken(ctx, apiEndpoint, cred.Token); err != nil {
	// 		return nil, err
	// 	}
	// default:
	// 	// TODO: move this error to Init
	// 	return nil, fmt.Errorf("Invalid configuration given for source. Name: %s, Type: %s", s.name, s.Type())
	// }

	s.models = make([]string, 0, s.filteredModelsCache.Count())
ModelsLoop:
	for _, repo := range s.filteredModelsCache.Keys() {
		repoURL, _ := s.filteredModelsCache.Get(repo)
		repoCtx := context.WithValue(ctx, MODEL, repoURL)
		if _, ok := s.repoInfoCache.get(repoURL); !ok {
			repoCtx.Logger().V(2).Info("Caching " + MODEL + " info")
			for {
				model, err := GetRepo(repoCtx, repo, MODEL, s.huggingfaceToken, s.conn.Endpoint)
				// if s.handleRateLimit(err) {
				// 	continue
				// }
				if err != nil {
					repoCtx.Logger().Error(err, "Failed to fetch model")
					continue ModelsLoop
				}
				var visibility source_metadatapb.Visibility
				if model.IsPrivate {
					visibility = source_metadatapb.Visibility_private
				} else {
					visibility = source_metadatapb.Visibility_public
				}
				s.repoInfoCache.put(repoURL, repoInfo{
					owner:        model.Owner,
					name:         strings.Split(model.RepoID, "/")[1],
					fullName:     model.RepoID,
					visibility:   visibility,
					resourceType: MODEL,
				})
				break
			}
		}
		s.models = append(s.models, repoURL)
	}

	s.spaces = make([]string, 0, s.filteredSpacesCache.Count())
SpacesLoop:
	for _, repo := range s.filteredSpacesCache.Keys() {
		repoURL, _ := s.filteredSpacesCache.Get(repo)
		repoCtx := context.WithValue(ctx, SPACE, repoURL)
		if _, ok := s.repoInfoCache.get(repoURL); !ok {
			repoCtx.Logger().V(2).Info("Caching " + SPACE + " info")
			for {
				space, err := GetRepo(repoCtx, repo, SPACE, s.huggingfaceToken, s.conn.Endpoint)
				// if s.handleRateLimit(err) {
				// 	continue
				// }
				if err != nil {
					repoCtx.Logger().Error(err, "Failed to fetch space")
					continue SpacesLoop
				}
				var visibility source_metadatapb.Visibility
				if space.IsPrivate {
					visibility = source_metadatapb.Visibility_private
				} else {
					visibility = source_metadatapb.Visibility_public
				}
				s.repoInfoCache.put(repoURL, repoInfo{
					owner:        space.Owner,
					name:         strings.Split(space.RepoID, "/")[1],
					fullName:     space.RepoID,
					visibility:   visibility,
					resourceType: SPACE,
				})
				break
			}
		}
		s.spaces = append(s.spaces, repoURL)
	}

	s.datasets = make([]string, 0, s.filteredDatasetsCache.Count())
DatasetsLoop:
	for _, repo := range s.filteredDatasetsCache.Keys() {
		repoURL, _ := s.filteredDatasetsCache.Get(repo)
		repoCtx := context.WithValue(ctx, DATASET, repoURL)
		if _, ok := s.repoInfoCache.get(repoURL); !ok {
			repoCtx.Logger().V(2).Info("Caching " + DATASET + " info")
			for {
				dataset, err := GetRepo(repoCtx, repo, DATASET, s.huggingfaceToken, s.conn.Endpoint)
				// if s.handleRateLimit(err) {
				// 	continue
				// }
				if err != nil {
					repoCtx.Logger().Error(err, "Failed to fetch dataset")
					continue DatasetsLoop
				}
				var visibility source_metadatapb.Visibility
				if dataset.IsPrivate {
					visibility = source_metadatapb.Visibility_private
				} else {
					visibility = source_metadatapb.Visibility_public
				}
				s.repoInfoCache.put(repoURL, repoInfo{
					owner:        dataset.Owner,
					name:         strings.Split(dataset.RepoID, "/")[1],
					fullName:     dataset.RepoID,
					visibility:   visibility,
					resourceType: DATASET,
				})
				break
			}
		}
		s.datasets = append(s.datasets, repoURL)
	}

	// huggingfaceModelsEnumerated.WithLabelValues(s.name).Set(float64(len(s.repos)))
	//"num_orgs", s.orgsCache.Count(), "num_members", len(s.memberCache)
	s.log.Info("Completed enumeration", "num_model", len(s.models), "num_space", len(s.spaces), "num_dataset", len(s.datasets))

	// We must sort the repos so we can resume later if necessary.
	sort.Strings(s.models)
	return installationClient, nil
}

// func (s *Source) enumerateUnauthenticated(ctx context.Context, apiEndpoint string) {
// 	ghClient, err := createGitHubClient(s.httpClient, apiEndpoint)
// 	if err != nil {
// 		s.log.Error(err, "error creating GitHub client")
// 	}
// 	s.apiClient = ghClient
// 	if s.orgsCache.Count() > unauthGithubOrgRateLimt {
// 		s.log.Info("You may experience rate limiting when using the unauthenticated GitHub api. Consider using an authenticated scan instead.")
// 	}

// 	for _, org := range s.orgsCache.Keys() {
// 		orgCtx := context.WithValue(ctx, "account", org)
// 		userType, err := s.getReposByOrgOrUser(ctx, org)
// 		if err != nil {
// 			orgCtx.Logger().Error(err, "error fetching repos for org or user")
// 			continue
// 		}

// 		if userType == organization && s.conn.ScanUsers {
// 			orgCtx.Logger().Info("WARNING: Enumerating unauthenticated does not support scanning organization members (--include-members)")
// 		}
// 	}
// }

// func (s *Source) enumerateWithToken(ctx context.Context, apiEndpoint, token string) error {
// 	// Needed for clones.
// 	s.githubToken = token

// 	// Needed to list repos.
// 	ts := oauth2.StaticTokenSource(
// 		&oauth2.Token{AccessToken: token},
// 	)
// 	s.httpClient.Transport = &oauth2.Transport{
// 		Base:   s.httpClient.Transport,
// 		Source: oauth2.ReuseTokenSource(nil, ts),
// 	}

// 	// If we're using public GitHub, make a regular client.
// 	// Otherwise, make an enterprise client.
// 	ghClient, err := createGitHubClient(s.httpClient, apiEndpoint)
// 	if err != nil {
// 		s.log.Error(err, "error creating GitHub client")
// 	}
// 	s.apiClient = ghClient

// 	ctx.Logger().V(1).Info("Enumerating with token", "endpoint", apiEndpoint)
// 	var ghUser *github.User
// 	for {
// 		ghUser, _, err = s.apiClient.Users.Get(ctx, "")
// 		if s.handleRateLimit(err) {
// 			continue
// 		}
// 		if err != nil {
// 			return fmt.Errorf("error getting user: %w", err)
// 		}
// 		break
// 	}

// 	specificScope := len(s.repos) > 0 || s.orgsCache.Count() > 0
// 	if !specificScope {
// 		// Enumerate the user's orgs and repos if none were specified.
// 		if err := s.getReposByUser(ctx, ghUser.GetLogin()); err != nil {
// 			s.log.Error(err, "Unable to fetch repos for the current user", "user", ghUser.GetLogin())
// 		}
// 		if err := s.addUserGistsToCache(ctx, ghUser.GetLogin()); err != nil {
// 			s.log.Error(err, "Unable to fetch gists for the current user", "user", ghUser.GetLogin())
// 		}

// 		isGHE := !strings.EqualFold(apiEndpoint, cloudEndpoint)
// 		if isGHE {
// 			s.addAllVisibleOrgs(ctx)
// 		} else {
// 			// Scan for orgs is default with a token.
// 			// GitHub App enumerates the repos that were assigned to it in GitHub App settings.
// 			s.addOrgsByUser(ctx, ghUser.GetLogin())
// 		}
// 	}

// 	if len(s.orgsCache.Keys()) > 0 {
// 		for _, org := range s.orgsCache.Keys() {
// 			orgCtx := context.WithValue(ctx, "account", org)
// 			userType, err := s.getReposByOrgOrUser(ctx, org)
// 			if err != nil {
// 				orgCtx.Logger().Error(err, "Unable to fetch repos for org or user")
// 				continue
// 			}

// 			if userType == organization && s.conn.ScanUsers {
// 				if err := s.addMembersByOrg(ctx, org); err != nil {
// 					orgCtx.Logger().Error(err, "Unable to add members for org")
// 				}
// 			}
// 		}

// 		if s.conn.ScanUsers && len(s.memberCache) > 0 {
// 			s.log.Info("Fetching repos for org members", "org_count", s.orgsCache.Count(), "member_count", len(s.memberCache))
// 			s.addReposForMembers(ctx)
// 		}
// 	}

// 	return nil
// }

// func createGitHubClient(httpClient *http.Client, apiEndpoint string) (*github.Client, error) {
// 	// If we're using public GitHub, make a regular client.
// 	// Otherwise, make an enterprise client.
// 	if strings.EqualFold(apiEndpoint, cloudEndpoint) {
// 		return github.NewClient(httpClient), nil
// 	}

// 	return github.NewClient(httpClient).WithEnterpriseURLs(apiEndpoint, apiEndpoint)
// }

func (s *Source) scanRepos(ctx context.Context, installationClient *http.Client, chunksChan chan *sources.Chunk, repos []string, resourceType string) error {
	var scannedCount uint64 = 1

	s.log.V(2).Info("Found "+resourceType+" to scan", "count", len(repos))

	// If there is resume information available, limit this scan to only the repos that still need scanning.
	reposToScan, progressIndexOffset := sources.FilterReposToResume(repos, s.GetProgress().EncodedResumeInfo)
	repos = reposToScan

	scanErrs := sources.NewScanErrors()
	// Setup scan options if it wasn't provided.
	if s.scanOptions == nil {
		s.scanOptions = &git.ScanOptions{}
	}

	for i, repoURL := range repos {
		i, repoURL := i, repoURL
		s.jobPool.Go(func() error {
			if common.IsDone(ctx) {
				return nil
			}

			// TODO: set progress complete is being called concurrently with i
			s.setProgressCompleteWithRepo(i, progressIndexOffset, repoURL, resourceType, repos)
			// Ensure the repo is removed from the resume info after being scanned.
			defer func(s *Source, repoURL string) {
				s.resumeInfoMutex.Lock()
				defer s.resumeInfoMutex.Unlock()
				s.resumeInfoSlice = sources.RemoveRepoFromResumeInfo(s.resumeInfoSlice, repoURL)
			}(s, repoURL)

			if !strings.HasSuffix(repoURL, ".git") {
				scanErrs.Add(fmt.Errorf("repo %s does not end in .git", repoURL))
				return nil
			}

			// Scan the repository
			repoInfo, ok := s.repoInfoCache.get(repoURL)

			if !ok {
				// This should never happen.
				err := fmt.Errorf("no repoInfo for URL: %s", repoURL)
				s.log.Error(err, "failed to scan "+resourceType)
				return nil
			}
			repoCtx := context.WithValues(ctx, resourceType, repoURL)
			duration, err := s.cloneAndScanRepo(repoCtx, repoURL, repoInfo, chunksChan)
			if err != nil {
				scanErrs.Add(err)
				return nil
			}

			// Scan discussions and PRs, if enabled.
			if s.includeDiscussions || s.includePrs {
				if err = s.scanDiscussions(repoCtx, repoInfo, chunksChan); err != nil {
					scanErrs.Add(fmt.Errorf("error scanning discussions/PRs in repo %s: %w", repoURL, err))
					return nil
				}
			}

			repoCtx.Logger().V(2).Info(fmt.Sprintf("scanned %d/%d "+resourceType+"s", scannedCount, len(s.models)), "duration_seconds", duration)
			//githubReposScanned.WithLabelValues(s.name).Inc()
			atomic.AddUint64(&scannedCount, 1)
			return nil
		})
	}

	_ = s.jobPool.Wait()
	if scanErrs.Count() > 0 {
		s.log.V(0).Info("failed to scan some repositories", "error_count", scanErrs.Count(), "errors", scanErrs.String())
	}
	s.SetProgressComplete(len(s.models), len(s.models), "Completed HuggingFace "+resourceType+" scan", "")
	return nil
}

func (s *Source) scan(ctx context.Context, installationClient *http.Client, chunksChan chan *sources.Chunk) error {
	s.scanRepos(ctx, installationClient, chunksChan, s.models, MODEL)
	s.scanRepos(ctx, installationClient, chunksChan, s.spaces, SPACE)
	s.scanRepos(ctx, installationClient, chunksChan, s.datasets, DATASET)
	return nil
}

func (s *Source) cloneAndScanRepo(ctx context.Context, repoURL string, repoInfo repoInfo, chunksChan chan *sources.Chunk) (time.Duration, error) {
	var duration time.Duration

	ctx.Logger().V(2).Info("attempting to clone %s", repoInfo.resourceType)
	path, repo, err := s.cloneRepo(ctx, repoURL)
	if err != nil {
		return duration, err
	}
	defer os.RemoveAll(path)

	var logger logr.Logger
	logger.V(2).Info("scanning %s", repoInfo.resourceType)

	start := time.Now()
	if err = s.git.ScanRepo(ctx, repo, path, s.scanOptions, sources.ChanReporter{Ch: chunksChan}); err != nil {
		return duration, fmt.Errorf("error scanning repo %s: %w", repoURL, err)
	}
	duration = time.Since(start)
	return duration, nil
}

var (
	rateLimitMu         sync.RWMutex
	rateLimitResumeTime time.Time
)

// handleRateLimit returns true if a rate limit was handled
//
// Unauthenticated users have a rate limit of 60 requests per hour.
// Authenticated users have a rate limit of 5,000 requests per hour,
// however, certain actions are subject to a stricter "secondary" limit.
// https://docs.github.com/en/rest/overview/rate-limits-for-the-rest-api
// func (s *Source) handleRateLimit(errIn error) bool {
// 	if errIn == nil {
// 		return false
// 	}

// 	rateLimitMu.RLock()
// 	resumeTime := rateLimitResumeTime
// 	rateLimitMu.RUnlock()

// 	var retryAfter time.Duration
// 	if resumeTime.IsZero() || time.Now().After(resumeTime) {
// 		rateLimitMu.Lock()

// 		var (
// 			now = time.Now()

// 			// GitHub has both primary (RateLimit) and secondary (AbuseRateLimit) errors.
// 			limitType  string
// 			rateLimit  *github.RateLimitError
// 			abuseLimit *github.AbuseRateLimitError
// 		)
// 		if errors.As(errIn, &rateLimit) {
// 			limitType = "primary"
// 			rate := rateLimit.Rate
// 			if rate.Remaining == 0 { // TODO: Will we ever receive a |RateLimitError| when remaining > 0?
// 				retryAfter = rate.Reset.Sub(now)
// 			}
// 		} else if errors.As(errIn, &abuseLimit) {
// 			limitType = "secondary"
// 			retryAfter = abuseLimit.GetRetryAfter()
// 		} else {
// 			rateLimitMu.Unlock()
// 			return false
// 		}

// 		jitter := time.Duration(rand.Intn(10)+1) * time.Second
// 		if retryAfter > 0 {
// 			retryAfter = retryAfter + jitter
// 			rateLimitResumeTime = now.Add(retryAfter)
// 			s.log.V(0).Info(fmt.Sprintf("exceeded %s rate limit", limitType), "retry_after", retryAfter.String(), "resume_time", rateLimitResumeTime.Format(time.RFC3339))
// 		} else {
// 			retryAfter = (5 * time.Minute) + jitter
// 			rateLimitResumeTime = now.Add(retryAfter)
// 			// TODO: Use exponential backoff instead of static retry time.
// 			s.log.V(0).Error(errIn, "unexpected rate limit error", "retry_after", retryAfter.String(), "resume_time", rateLimitResumeTime.Format(time.RFC3339))
// 		}

// 		rateLimitMu.Unlock()
// 	} else {
// 		retryAfter = time.Until(resumeTime)
// 	}

// 	githubNumRateLimitEncountered.WithLabelValues(s.name).Inc()
// 	time.Sleep(retryAfter)
// 	githubSecondsSpentRateLimited.WithLabelValues(s.name).Add(retryAfter.Seconds())
// 	return true
// }

// func (s *Source) addAllVisibleOrgs(ctx context.Context) {
// 	s.log.V(2).Info("enumerating all visible organizations on GHE")
// 	// Enumeration on this endpoint does not use pages it uses a since ID.
// 	// The endpoint will return organizations with an ID greater than the given since ID.
// 	// Empty org response is our cue to break the enumeration loop.
// 	orgOpts := &github.OrganizationsListOptions{
// 		Since: 0,
// 		ListOptions: github.ListOptions{
// 			PerPage: defaultPagination,
// 		},
// 	}
// 	for {
// 		orgs, _, err := s.apiClient.Organizations.ListAll(ctx, orgOpts)
// 		if s.handleRateLimit(err) {
// 			continue
// 		}
// 		if err != nil {
// 			s.log.Error(err, "could not list all organizations")
// 			return
// 		}

// 		if len(orgs) == 0 {
// 			break
// 		}

// 		lastOrgID := *orgs[len(orgs)-1].ID
// 		s.log.V(2).Info(fmt.Sprintf("listed organization IDs %d through %d", orgOpts.Since, lastOrgID))
// 		orgOpts.Since = lastOrgID

// 		for _, org := range orgs {
// 			var name string
// 			switch {
// 			case org.Name != nil:
// 				name = *org.Name
// 			case org.Login != nil:
// 				name = *org.Login
// 			default:
// 				continue
// 			}
// 			s.orgsCache.Set(name, name)
// 			s.log.V(2).Info("adding organization for repository enumeration", "id", org.ID, "name", name)
// 		}
// 	}
// }

// func (s *Source) addOrgsByUser(ctx context.Context, user string) {
// 	orgOpts := &github.ListOptions{
// 		PerPage: defaultPagination,
// 	}
// 	logger := s.log.WithValues("user", user)
// 	for {
// 		orgs, resp, err := s.apiClient.Organizations.List(ctx, "", orgOpts)
// 		if s.handleRateLimit(err) {
// 			continue
// 		}
// 		if err != nil {
// 			logger.Error(err, "Could not list organizations")
// 			return
// 		}

// 		logger.V(2).Info("Listed orgs", "page", orgOpts.Page, "last_page", resp.LastPage)
// 		for _, org := range orgs {
// 			if org.Login == nil {
// 				continue
// 			}
// 			s.orgsCache.Set(*org.Login, *org.Login)
// 		}
// 		if resp.NextPage == 0 {
// 			break
// 		}
// 		orgOpts.Page = resp.NextPage
// 	}
// }

// func (s *Source) addMembersByOrg(ctx context.Context, org string) error {
// 	opts := &github.ListMembersOptions{
// 		PublicOnly: false,
// 		ListOptions: github.ListOptions{
// 			PerPage: membersAppPagination,
// 		},
// 	}

// 	logger := s.log.WithValues("org", org)
// 	for {
// 		members, res, err := s.apiClient.Organizations.ListMembers(ctx, org, opts)
// 		if s.handleRateLimit(err) {
// 			continue
// 		}
// 		if err != nil || len(members) == 0 {
// 			return fmt.Errorf("could not list organization members: account may not have access to list organization members %w", err)
// 		}

// 		logger.V(2).Info("Listed members", "page", opts.Page, "last_page", res.LastPage)
// 		for _, m := range members {
// 			usr := m.Login
// 			if usr == nil || *usr == "" {
// 				continue
// 			}
// 			if _, ok := s.memberCache[*usr]; !ok {
// 				s.memberCache[*usr] = struct{}{}
// 			}
// 		}
// 		if res.NextPage == 0 {
// 			break
// 		}
// 		opts.Page = res.NextPage
// 	}

// 	return nil
// }

// setProgressCompleteWithRepo calls the s.SetProgressComplete after safely setting up the encoded resume info string.
func (s *Source) setProgressCompleteWithRepo(index int, offset int, repoURL string, resourceType string, repos []string) {
	s.resumeInfoMutex.Lock()
	defer s.resumeInfoMutex.Unlock()

	// Add the repoURL to the resume info slice.
	s.resumeInfoSlice = append(s.resumeInfoSlice, repoURL)
	sort.Strings(s.resumeInfoSlice)

	// Make the resume info string from the slice.
	encodedResumeInfo := sources.EncodeResumeInfo(s.resumeInfoSlice)

	s.SetProgressComplete(index+offset, len(repos)+offset, fmt.Sprintf("%ss: %s", resourceType, repoURL), encodedResumeInfo)
}

const initialPage = 1 // page to start listing from

func (s *Source) scanDiscussions(ctx context.Context, repoInfo repoInfo, chunksChan chan *sources.Chunk) error {
	// ToDo: Deal with rate limits + pagination
	discussions, err := ListDiscussions(ctx, s.huggingfaceToken, s.conn.Endpoint, repoInfo)
	if err != nil {
		return err
	}

	for _, discussion := range discussions.Discussions {
		if !discussion.IsPR && s.includeDiscussions {
			d, err := GetDiscussionByID(ctx, s.huggingfaceToken, s.conn.Endpoint, repoInfo, discussion.GetID())
			if err != nil {
				return err
			}

			// chunk discussion and comments
			// Note: there is no discussion "description" or similar to chunk, only comments
			if err = s.chunkDiscussionComments(ctx, repoInfo, d, chunksChan); err != nil {
				return err
			}
		} else if discussion.IsPR && s.includePrs {
			// ToDo: Process PR file changes.
			d, err := GetDiscussionByID(ctx, s.huggingfaceToken, s.conn.Endpoint, repoInfo, discussion.GetID())
			if err != nil {
				return err
			}

			// chunk discussion and comments
			if err = s.chunkDiscussionComments(ctx, repoInfo, d, chunksChan); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Source) chunkDiscussionComments(ctx context.Context, repoInfo repoInfo, discussion Discussion, chunksChan chan *sources.Chunk) error {
	for _, comment := range discussion.Events {
		chunk := &sources.Chunk{
			SourceName: s.name,
			SourceID:   s.SourceID(),
			JobID:      s.JobID(),
			SourceType: s.Type(),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Huggingface{
					Huggingface: &source_metadatapb.Huggingface{
						Link:       sanitizer.UTF8(s.conn.Endpoint + "/" + discussion.GetDiscussionHTMLPath() + "#" + comment.GetID()),
						Username:   sanitizer.UTF8(comment.GetAuthor()),
						Repository: sanitizer.UTF8(s.conn.Endpoint + "/" + discussion.GetRepoHTMLPath()),
						Timestamp:  sanitizer.UTF8(comment.GetCreatedAt()),
						Visibility: repoInfo.visibility,
					},
				},
			},
			Data:   []byte(comment.Data.Latest.Raw),
			Verify: s.verify,
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case chunksChan <- chunk:
		}
	}
	return nil
}

// ToDo: Evaluate if this is needed
// func (s *Source) scanTargets(ctx context.Context, targets []sources.ChunkingTarget, chunksChan chan *sources.Chunk) error {
// 	for _, tgt := range targets {
// 		if err := s.scanTarget(ctx, tgt, chunksChan); err != nil {
// 			ctx.Logger().Error(err, "error scanning target")
// 		}
// 	}

// 	return nil
// }

// func (s *Source) scanTarget(ctx context.Context, target sources.ChunkingTarget, chunksChan chan *sources.Chunk) error {
// 	metaType, ok := target.QueryCriteria.GetData().(*source_metadatapb.MetaData_Huggingface)
// 	if !ok {
// 		return fmt.Errorf("unable to cast metadata type for targeted scan")
// 	}
// 	meta := metaType.HuggingFace

// 	u, err := url.Parse(meta.GetLink())
// 	if err != nil {
// 		return fmt.Errorf("unable to parse HuggingFace URL: %w", err)
// 	}

// 	// The owner is the third segment and the repo is the fourth segment of the path.
// 	// Ex: https://hugginface.com/spaces/owner/repo/.....
// 	segments := strings.Split(u.Path, "/")
// 	if len(segments) < 4 {
// 		return fmt.Errorf("invalid HuggingFace URL")
// 	}

// 	qry := commitQuery{
// 		repo:     segments[3],
// 		owner:    segments[2],
// 		typ:      segments[1],
// 		sha:      meta.GetCommit(),
// 		filename: meta.GetFile(),
// 	}
// 	res, err := s.getDiffForFileInCommit(ctx, qry)
// 	if err != nil {
// 		return err
// 	}
// 	chunk := &sources.Chunk{
// 		SourceType: s.Type(),
// 		SourceName: s.name,
// 		SourceID:   s.SourceID(),
// 		JobID:      s.JobID(),
// 		SecretID:   target.SecretID,
// 		Data:       []byte(res),
// 		SourceMetadata: &source_metadatapb.MetaData{
// 			Data: &source_metadatapb.MetaData_Github{Github: meta},
// 		},
// 		Verify: s.verify,
// 	}

// 	return common.CancellableWrite(ctx, chunksChan, chunk)
// }
