package huggingface

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gobwas/glob"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
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
	BucketsRoute      = "buckets"
	DiscussionsRoute  = "discussions"
	APIRoute          = "api"
	DATASET           = "dataset"
	MODEL             = "model"
	SPACE             = "space"
	BUCKET            = "bucket"
	defaultPagination = 100

	// bucketsPagination is the page size for bucket listing endpoints,
	// which default to 100 items per page (5000 max).
	bucketsPagination = 5000

	// listReposLimit is the page size ListReposByAuthor asks for. The listing is
	// not paged, so a full page may mean repos were missed.
	listReposLimit = 1000
)

type resourceType string

type Source struct {
	name             string
	huggingfaceToken string

	sourceID               sources.SourceID
	jobID                  sources.JobID
	verify                 bool
	useCustomContentWriter bool
	orgsCache              cache.Cache[string]
	usersCache             cache.Cache[string]

	models   []string
	spaces   []string
	datasets []string
	buckets  []string

	filteredModelsCache   *filteredRepoCache
	filteredSpacesCache   *filteredRepoCache
	filteredDatasetsCache *filteredRepoCache
	filteredBucketsCache  *filteredRepoCache

	repoInfoCache repoInfoCache

	git *git.Git

	scanOptions *git.ScanOptions

	apiClient       *HFClient
	conn            *sourcespb.Huggingface
	jobPool         *errgroup.Group
	resumeInfoMutex sync.Mutex
	resumeInfoSlice []string

	skipAllModels      bool
	skipAllSpaces      bool
	skipAllDatasets    bool
	skipAllBuckets     bool
	includeDiscussions bool
	includePrs         bool

	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

// Ensure the Source satisfies the interfaces at compile time
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)

// WithCustomContentWriter sets the useCustomContentWriter flag on the source.
func (s *Source) WithCustomContentWriter() { s.useCustomContentWriter = true }

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

func (s *Source) newFilteredRepoCache(ctx context.Context, c cache.Cache[string], include, exclude []string) *filteredRepoCache {
	includeGlobs := make([]glob.Glob, 0, len(include))
	excludeGlobs := make([]glob.Glob, 0, len(exclude))
	for _, ig := range include {
		g, err := glob.Compile(ig)
		if err != nil {
			ctx.Logger().Error(err, "Invalid include glob, ignoring it", "glob", ig)
			continue
		}
		includeGlobs = append(includeGlobs, g)
	}
	for _, eg := range exclude {
		g, err := glob.Compile(eg)
		if err != nil {
			ctx.Logger().Error(err, "Invalid exclude glob, ignoring it", "glob", eg)
			continue
		}
		excludeGlobs = append(excludeGlobs, g)
	}
	return &filteredRepoCache{Cache: c, include: includeGlobs, exclude: excludeGlobs}
}

// Set overrides the cache.Cache Set method to filter out repos based on
// include and exclude globs.
func (c *filteredRepoCache) Set(key, val string) {
	if c.skipReason(key) != "" {
		return
	}
	c.Cache.Set(key, val)
}

// skipReason says why the include and exclude globs filter out a repo, or ""
// if they keep it.
func (c *filteredRepoCache) skipReason(key string) string {
	if c.ignoreRepo(key) {
		return "matches ignore filter"
	}
	if !c.includeRepo(key) {
		return "not in include filter"
	}
	return ""
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
func (s *Source) Init(ctx context.Context, name string, jobID sources.JobID, sourceID sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	err := git.CmdCheck()
	if err != nil {
		return err
	}

	s.name = name
	s.sourceID = sourceID
	s.jobID = jobID
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)

	var conn sourcespb.Huggingface
	err = anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}
	s.conn = &conn

	s.orgsCache = simple.NewCache[string]()
	for _, org := range s.conn.Organizations {
		s.orgsCache.Set(org, org)
	}

	s.usersCache = simple.NewCache[string]()
	for _, user := range s.conn.Users {
		s.usersCache.Set(user, user)
	}

	// Verify ignore and include models, spaces, and datasets are valid
	// this ensures that calling --org <org> --ignore-model <org/model> contains the proper
	// repo format of org/model. Otherwise, we would scan the entire org.
	if err := s.validateIgnoreIncludeRepos(); err != nil {
		return err
	}

	s.filteredModelsCache = s.newFilteredRepoCache(ctx, simple.NewCache[string](),
		append(s.conn.GetModels(), s.conn.GetIncludeModels()...),
		s.conn.GetIgnoreModels(),
	)

	s.filteredSpacesCache = s.newFilteredRepoCache(ctx, simple.NewCache[string](),
		append(s.conn.GetSpaces(), s.conn.GetIncludeSpaces()...),
		s.conn.GetIgnoreSpaces(),
	)

	s.filteredDatasetsCache = s.newFilteredRepoCache(ctx, simple.NewCache[string](),
		append(s.conn.GetDatasets(), s.conn.GetIncludeDatasets()...),
		s.conn.GetIgnoreDatasets(),
	)

	s.filteredBucketsCache = s.newFilteredRepoCache(ctx, simple.NewCache[string](),
		append(s.conn.GetBuckets(), s.conn.GetIncludeBuckets()...),
		s.conn.GetIgnoreBuckets(),
	)

	s.models = initializeRepos(ctx, s.filteredModelsCache, s.conn.Models, fmt.Sprintf("%s/%s.git", s.conn.Endpoint, "%s"))
	s.spaces = initializeRepos(ctx, s.filteredSpacesCache, s.conn.Spaces, fmt.Sprintf("%s/%s/%s.git", s.conn.Endpoint, SpacesRoute, "%s"))
	s.datasets = initializeRepos(ctx, s.filteredDatasetsCache, s.conn.Datasets, fmt.Sprintf("%s/%s/%s.git", s.conn.Endpoint, DatasetsRoute, "%s"))
	// Buckets are not git repos; they are keyed by their plain "namespace/name" ID.
	s.buckets = initializeRepos(ctx, s.filteredBucketsCache, s.conn.Buckets, "%s")
	s.repoInfoCache = newRepoInfoCache()

	s.includeDiscussions = s.conn.IncludeDiscussions
	s.includePrs = s.conn.IncludePrs

	cfg := &git.Config{
		SourceName:  s.name,
		JobID:       s.jobID,
		SourceID:    s.sourceID,
		SourceType:  s.Type(),
		Verify:      s.verify,
		Concurrency: concurrency,
		SourceMetadataFunc: func(info git.SourceMetadataInfo) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Huggingface{
					Huggingface: &source_metadatapb.Huggingface{
						Commit:       sanitizer.UTF8(info.Commit),
						File:         sanitizer.UTF8(info.File),
						Email:        sanitizer.UTF8(info.Email),
						Repository:   sanitizer.UTF8(info.Repository),
						Link:         giturl.GenerateLink(info.Repository, info.Commit, info.File, info.Line),
						Timestamp:    sanitizer.UTF8(info.Timestamp),
						Line:         info.Line,
						Visibility:   s.visibilityOf(ctx, info.Repository),
						ResourceType: s.getResourceType(ctx, info.Repository),
					},
				},
			}
		},
		UseCustomContentWriter: s.useCustomContentWriter,
	}
	s.git = git.NewGit(cfg)

	s.huggingfaceToken = s.conn.GetToken()
	s.apiClient = NewHFClient(s.conn.Endpoint, s.huggingfaceToken, 10*time.Second)

	s.skipAllModels = s.conn.SkipAllModels
	s.skipAllSpaces = s.conn.SkipAllSpaces
	s.skipAllDatasets = s.conn.SkipAllDatasets
	s.skipAllBuckets = s.conn.SkipAllBuckets

	ctx.Logger().V(1).Info("Hugging Face source initialized",
		"endpoint", redactURL(s.conn.Endpoint),
		"auth_type", authType(s.conn),
		"organizations", len(s.conn.Organizations),
		"users", len(s.conn.Users),
		"models", len(s.models),
		"spaces", len(s.spaces),
		"datasets", len(s.datasets),
		"buckets", len(s.buckets),
		"skip_all_models", s.skipAllModels,
		"skip_all_spaces", s.skipAllSpaces,
		"skip_all_datasets", s.skipAllDatasets,
		"skip_all_buckets", s.skipAllBuckets,
		"include_discussions", s.includeDiscussions,
		"include_prs", s.includePrs,
		"concurrency", concurrency,
	)

	return nil
}

// redactURL hides the password in a URL before it is logged. Repo URLs are
// built from the configured endpoint, which could carry user:pass. Log fields
// and error values are not covered by global redaction, so this is the only
// guard.
func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid URL>"
	}
	return u.Redacted()
}

// authType names the credential type for logs, never the credential.
func authType(conn *sourcespb.Huggingface) string {
	switch conn.GetCredential().(type) {
	case *sourcespb.Huggingface_Token:
		return "token"
	case *sourcespb.Huggingface_Unauthenticated:
		return "unauthenticated"
	default:
		return "none"
	}
}

func (s *Source) validateIgnoreIncludeRepos() error {
	if err := verifySlashSeparatedStrings(s.conn.IgnoreModels); err != nil {
		return err
	}
	if err := verifySlashSeparatedStrings(s.conn.IncludeModels); err != nil {
		return err
	}
	if err := verifySlashSeparatedStrings(s.conn.IgnoreSpaces); err != nil {
		return err
	}
	if err := verifySlashSeparatedStrings(s.conn.IncludeSpaces); err != nil {
		return err
	}
	if err := verifySlashSeparatedStrings(s.conn.IgnoreDatasets); err != nil {
		return err
	}
	if err := verifySlashSeparatedStrings(s.conn.IncludeDatasets); err != nil {
		return err
	}
	if err := verifySlashSeparatedStrings(s.conn.IgnoreBuckets); err != nil {
		return err
	}
	if err := verifySlashSeparatedStrings(s.conn.IncludeBuckets); err != nil {
		return err
	}
	return nil
}

func verifySlashSeparatedStrings(s []string) error {
	for _, str := range s {
		if !strings.Contains(str, "/") {
			return fmt.Errorf("invalid owner/repo: %s", str)
		}
	}
	return nil
}

func initializeRepos(ctx context.Context, cache *filteredRepoCache, repos []string, urlPattern string) []string {
	returnRepos := make([]string, 0)
	for _, repo := range repos {
		if cache.ignoreRepo(repo) {
			ctx.Logger().V(4).Info("Skipping repo", "repo", repo, "reason", "matches ignore filter")
			continue
		}
		url := fmt.Sprintf(urlPattern, repo)
		cache.Set(repo, url)
		returnRepos = append(returnRepos, repo)
	}
	return returnRepos
}

func (s *Source) getResourceType(ctx context.Context, repoURL string) string {
	repoInfo, ok := s.repoInfoCache.get(repoURL)
	if !ok {
		// This should never happen.
		err := fmt.Errorf("no repoInfo for URL: %s", redactURL(repoURL))
		ctx.Logger().Error(err, "failed to get repository resource type")
		return ""
	}

	return string(repoInfo.resourceType)
}

func (s *Source) visibilityOf(ctx context.Context, repoURL string) source_metadatapb.Visibility {
	repoInfo, ok := s.repoInfoCache.get(repoURL)
	if !ok {
		// This should never happen.
		err := fmt.Errorf("no repoInfo for URL: %s", redactURL(repoURL))
		ctx.Logger().Error(err, "failed to get repository visibility")
		return source_metadatapb.Visibility_unknown
	}

	return repoInfo.visibility
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, targets ...sources.ChunkingTarget) error {
	err := s.enumerate(ctx)
	if err != nil {
		return err
	}
	return s.scan(ctx, chunksChan)
}

func (s *Source) enumerate(ctx context.Context) error {
	s.enumerateAuthors(ctx)

	s.models = make([]string, 0, s.filteredModelsCache.Count())
	for _, repo := range s.filteredModelsCache.Keys() {
		if err := s.cacheRepoInfo(ctx, repo, MODEL, s.filteredModelsCache); err != nil {
			continue
		}
	}

	s.spaces = make([]string, 0, s.filteredSpacesCache.Count())
	for _, repo := range s.filteredSpacesCache.Keys() {
		if err := s.cacheRepoInfo(ctx, repo, SPACE, s.filteredSpacesCache); err != nil {
			continue
		}
	}

	s.datasets = make([]string, 0, s.filteredDatasetsCache.Count())
	for _, repo := range s.filteredDatasetsCache.Keys() {
		if err := s.cacheRepoInfo(ctx, repo, DATASET, s.filteredDatasetsCache); err != nil {
			continue
		}
	}

	s.buckets = make([]string, 0, s.filteredBucketsCache.Count())
	for _, bucket := range s.filteredBucketsCache.Keys() {
		if err := s.cacheBucketInfo(ctx, bucket); err != nil {
			continue
		}
	}

	ctx.Logger().Info("Completed enumeration", "num_models", len(s.models), "num_spaces", len(s.spaces), "num_datasets", len(s.datasets), "num_buckets", len(s.buckets))

	// We must sort the repos so we can resume later if necessary.
	sort.Strings(s.models)
	sort.Strings(s.datasets)
	sort.Strings(s.spaces)
	sort.Strings(s.buckets)
	return nil
}

func (s *Source) cacheRepoInfo(ctx context.Context, repo string, repoType string, repoCache *filteredRepoCache) error {
	repoURL, _ := repoCache.Get(repo)
	repoCtx := context.WithValue(ctx, repoType, redactURL(repoURL))

	if _, ok := s.repoInfoCache.get(repoURL); !ok {
		repoCtx.Logger().V(2).Info("Caching repo info")
		repo, err := s.apiClient.GetRepo(repoCtx, repo, repoType)
		if err != nil {
			repoCtx.Logger().Error(err, "Failed to fetch repo info")
			return err
		}
		// check if repo empty
		if repo.RepoID == "" {
			repoCtx.Logger().Error(errors.New("repo not found"), "Skipping repo")
			return nil
		}
		// Legacy model IDs like "gpt2" have no owner part, so don't index past the slash.
		name := repo.RepoID
		if _, after, ok := strings.Cut(repo.RepoID, "/"); ok {
			name = after
		}
		s.repoInfoCache.put(repoURL, repoInfo{
			owner:        repo.Owner,
			name:         name,
			fullName:     repo.RepoID,
			visibility:   getVisibility(repo.IsPrivate),
			resourceType: resourceType(repoType),
		})
	}
	s.updateRepoLists(repoURL, repoType)
	return nil
}

func getVisibility(isPrivate bool) source_metadatapb.Visibility {
	if isPrivate {
		return source_metadatapb.Visibility_private
	}
	return source_metadatapb.Visibility_public
}

func (s *Source) updateRepoLists(repoURL string, repoType string) {
	switch repoType {
	case MODEL:
		s.models = append(s.models, repoURL)
	case SPACE:
		s.spaces = append(s.spaces, repoURL)
	case DATASET:
		s.datasets = append(s.datasets, repoURL)
	}
}

func (s *Source) fetchAndCacheRepos(ctx context.Context, resourceType string, org string) error {
	var repos []Repo
	var err error
	var url string
	var filteredCache *filteredRepoCache
	switch resourceType {
	case MODEL:
		filteredCache = s.filteredModelsCache
		url = fmt.Sprintf("%s/%s.git", s.conn.Endpoint, "%s")
		repos, err = s.apiClient.ListReposByAuthor(ctx, MODEL, org)
	case SPACE:
		filteredCache = s.filteredSpacesCache
		url = fmt.Sprintf("%s/%s/%s.git", s.conn.Endpoint, SpacesRoute, "%s")
		repos, err = s.apiClient.ListReposByAuthor(ctx, SPACE, org)
	case DATASET:
		filteredCache = s.filteredDatasetsCache
		url = fmt.Sprintf("%s/%s/%s.git", s.conn.Endpoint, DatasetsRoute, "%s")
		repos, err = s.apiClient.ListReposByAuthor(ctx, DATASET, org)
	}
	if err != nil {
		return err
	}
	ctx.Logger().V(2).Info("Listed repos", "resource_type", resourceType, "count", len(repos))
	if len(repos) >= listReposLimit {
		ctx.Logger().Info("Repo listing hit the API limit, some repos may be missing",
			"resource_type", resourceType,
			"limit", listReposLimit,
		)
	}

	for _, repo := range repos {
		if reason := filteredCache.skipReason(repo.RepoID); reason != "" {
			ctx.Logger().V(4).Info("Skipping repo", "repo", repo.RepoID, "reason", reason)
			continue
		}
		repoURL := fmt.Sprintf(url, repo.RepoID)
		filteredCache.Set(repo.RepoID, repoURL)
		if err := s.cacheRepoInfo(ctx, repo.RepoID, resourceType, filteredCache); err != nil {
			continue
		}
	}
	return nil
}

func (s *Source) enumerateAuthors(ctx context.Context) {
	for _, org := range s.orgsCache.Keys() {
		orgCtx := context.WithValue(ctx, "organization", org)
		if !s.skipAllModels {
			if err := s.fetchAndCacheRepos(orgCtx, MODEL, org); err != nil {
				orgCtx.Logger().Error(err, "Failed to fetch models for organization")
				continue
			}
		}
		if !s.skipAllSpaces {
			if err := s.fetchAndCacheRepos(orgCtx, SPACE, org); err != nil {
				orgCtx.Logger().Error(err, "Failed to fetch spaces for organization")
				continue
			}
		}
		if !s.skipAllDatasets {
			if err := s.fetchAndCacheRepos(orgCtx, DATASET, org); err != nil {
				orgCtx.Logger().Error(err, "Failed to fetch datasets for organization")
				continue
			}
		}
		if !s.skipAllBuckets {
			if err := s.fetchAndCacheBuckets(orgCtx, org); err != nil {
				orgCtx.Logger().Error(err, "Failed to fetch buckets for organization")
				continue
			}
		}
	}
	for _, user := range s.usersCache.Keys() {
		userCtx := context.WithValue(ctx, "user", user)
		if !s.skipAllModels {
			if err := s.fetchAndCacheRepos(userCtx, MODEL, user); err != nil {
				userCtx.Logger().Error(err, "Failed to fetch models for user")
				continue
			}
		}
		if !s.skipAllSpaces {
			if err := s.fetchAndCacheRepos(userCtx, SPACE, user); err != nil {
				userCtx.Logger().Error(err, "Failed to fetch spaces for user")
				continue
			}
		}
		if !s.skipAllDatasets {
			if err := s.fetchAndCacheRepos(userCtx, DATASET, user); err != nil {
				userCtx.Logger().Error(err, "Failed to fetch datasets for user")
				continue
			}
		}
		if !s.skipAllBuckets {
			if err := s.fetchAndCacheBuckets(userCtx, user); err != nil {
				userCtx.Logger().Error(err, "Failed to fetch buckets for user")
				continue
			}
		}
	}
}

func (s *Source) scanRepos(ctx context.Context, chunksChan chan *sources.Chunk, resourceType string) error {
	var scannedCount uint64

	repos := s.getReposListByType(resourceType)

	ctx.Logger().V(1).Info("Scanning repos", "resource_type", resourceType, "count", len(repos))

	// If there is resume information available, limit this scan to only the repos that still need scanning.
	reposToScan, progressIndexOffset := sources.FilterReposToResume(repos, s.GetProgress().EncodedResumeInfo)
	repos = reposToScan
	if progressIndexOffset > 0 {
		ctx.Logger().V(1).Info("Resuming from saved progress",
			"resource_type", resourceType,
			"already_scanned", progressIndexOffset,
			"remaining", len(repos),
		)
	}

	scanErrs := sources.NewScanErrors()

	if s.scanOptions == nil {
		s.scanOptions = &git.ScanOptions{}
	}

	for i, repoURL := range repos {
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

			// Scan the repository
			repoInfo, ok := s.repoInfoCache.get(repoURL)
			if !ok {
				// This should never happen.
				err := fmt.Errorf("no repoInfo for URL: %s", redactURL(repoURL))
				ctx.Logger().Error(err, "Failed to scan repo", "resource_type", resourceType)
				return nil
			}
			repoCtx := context.WithValues(ctx, resourceType, redactURL(repoURL))
			repoCtx.Logger().V(2).Info("Scanning repo")
			duration, err := s.cloneAndScanRepo(repoCtx, repoURL, repoInfo, chunksChan)
			if err != nil {
				scanErrs.Add(err)
				return nil
			}

			// Scan discussions and PRs, if enabled.
			if s.includeDiscussions || s.includePrs {
				if err = s.scanDiscussions(repoCtx, repoInfo, chunksChan); err != nil {
					scanErrs.Add(fmt.Errorf("error scanning discussions/PRs in repo %s: %w", redactURL(repoURL), err))
					return nil
				}
			}

			repoCtx.Logger().V(2).Info("Finished scanning repo",
				"scanned", atomic.AddUint64(&scannedCount, 1),
				"total", len(repos),
				"duration", duration,
			)
			return nil
		})
	}

	_ = s.jobPool.Wait()
	if scanErrs.Count() > 0 {
		ctx.Logger().Error(scanErrs.Errors(), "Failed to scan some repos",
			"resource_type", resourceType,
			"error_count", scanErrs.Count(),
		)
	}
	s.SetProgressComplete(len(repos), len(repos), "Completed HuggingFace "+resourceType+" scan", "")
	return nil
}

func (s *Source) getReposListByType(resourceType string) []string {
	switch resourceType {
	case MODEL:
		return s.models
	case SPACE:
		return s.spaces
	case DATASET:
		return s.datasets
	}
	return nil
}

func (s *Source) scan(ctx context.Context, chunksChan chan *sources.Chunk) error {
	if err := s.scanRepos(ctx, chunksChan, MODEL); err != nil {
		return err
	}
	if err := s.scanRepos(ctx, chunksChan, SPACE); err != nil {
		return err
	}
	if err := s.scanRepos(ctx, chunksChan, DATASET); err != nil {
		return err
	}
	if err := s.scanBuckets(ctx, chunksChan); err != nil {
		return err
	}
	return nil
}

func (s *Source) cloneAndScanRepo(ctx context.Context, repoURL string, repoInfo repoInfo, chunksChan chan *sources.Chunk) (time.Duration, error) {
	path, repo, err := s.cloneRepo(ctx, repoURL)
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.RemoveAll(path) }()

	ctx.Logger().V(3).Info("Cloned repo")

	start := time.Now()
	if err = s.git.ScanRepo(ctx, repo, path, s.scanOptions, sources.ChanReporter{Ch: chunksChan}); err != nil {
		return 0, fmt.Errorf("error scanning repo %s: %w", redactURL(repoURL), err)
	}
	return time.Since(start), nil
}

// setProgressCompleteWithRepo calls the s.SetProgressComplete after safely setting up the encoded resume info string.
func (s *Source) setProgressCompleteWithRepo(index int, offset int, repoURL string, resourceType string, repos []string) {
	s.resumeInfoMutex.Lock()
	defer s.resumeInfoMutex.Unlock()

	// Add the repoURL to the resume info slice.
	s.resumeInfoSlice = append(s.resumeInfoSlice, repoURL)
	sort.Strings(s.resumeInfoSlice)

	// Make the resume info string from the slice.
	encodedResumeInfo := sources.EncodeResumeInfo(s.resumeInfoSlice)
	s.SetProgressComplete(index+offset, len(repos)+offset, fmt.Sprintf("%ss: %s", resourceType, redactURL(repoURL)), encodedResumeInfo)
}

func (s *Source) scanDiscussions(ctx context.Context, repoInfo repoInfo, chunksChan chan *sources.Chunk) error {
	discussions, err := s.apiClient.ListDiscussions(ctx, repoInfo)
	if err != nil {
		return err
	}
	ctx.Logger().V(3).Info("Listed discussions", "count", len(discussions.Discussions))
	for _, discussion := range discussions.Discussions {
		if discussion.IsPR && !s.includePrs {
			ctx.Logger().V(4).Info("Skipping discussion", "discussion", discussion.GetID(), "is_pr", true, "reason", "PRs not included")
			continue
		}
		if !discussion.IsPR && !s.includeDiscussions {
			ctx.Logger().V(4).Info("Skipping discussion", "discussion", discussion.GetID(), "is_pr", false, "reason", "discussions not included")
			continue
		}
		d, err := s.apiClient.GetDiscussionByID(ctx, repoInfo, discussion.GetID())
		if err != nil {
			return err
		}
		ctx.Logger().V(3).Info("Scanning discussion",
			"discussion", discussion.GetID(),
			"is_pr", discussion.IsPR,
			"comments", len(d.Events),
		)
		// Note: there is no discussion "description" or similar to chunk, only comments
		if err = s.chunkDiscussionComments(ctx, repoInfo, d, chunksChan); err != nil {
			return err
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
						Link:       sanitizer.UTF8(fmt.Sprintf("%s/%s#%s", s.conn.Endpoint, discussion.GetDiscussionPath(), comment.GetID())),
						Username:   sanitizer.UTF8(comment.GetAuthor()),
						Repository: sanitizer.UTF8(fmt.Sprintf("%s/%s", s.conn.Endpoint, discussion.GetGitPath())),
						Timestamp:  sanitizer.UTF8(comment.GetCreatedAt()),
						Visibility: repoInfo.visibility,
					},
				},
			},
			Data:         []byte(comment.Data.Latest.Raw),
			SourceVerify: s.verify,
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case chunksChan <- chunk:
		}
	}
	return nil
}
