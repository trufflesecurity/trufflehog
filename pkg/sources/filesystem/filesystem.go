package filesystem

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/lru"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM

type Source struct {
	name           string
	sourceId       sources.SourceID
	jobId          sources.JobID
	concurrency    int
	verify         bool
	paths          []string
	log            logr.Logger
	filter         *common.Filter
	skipBinaries   bool
	followSymlinks bool
	// scanRootPaths tracks the top-level directories/files being scanned.
	// Used to enforce depth-1 symlink following: only symlinks that are direct children
	// of these paths will be followed, preventing deep symlink chains.
	scanRootPaths map[string]struct{}
	// visitedPaths is an LRU cache tracking canonical paths of followed symlinks.
	// Only created when followSymlinks=true to avoid memory overhead.
	//
	// Why LRU cache instead of a map:
	// - Bounded memory: Limits to 10k paths (~1MB) even for massive directory trees
	// - Per-path reset: Cache is recreated for each scan path to prevent accumulation
	// - Loop detection: Prevents scanning the same file multiple times via different symlinks
	//
	// Why depth-1 limiting:
	// - Prevents infinite loops: Symlink chains (A->B->C->...) are limited
	// - Predictable behavior: Users know exactly which symlinks will be followed
	visitedPaths cache.Cache[struct{}]
	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

// Ensure the Source satisfies the interfaces at compile time
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)
var _ sources.SourceUnitEnumChunker = (*Source)(nil)

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

// Init returns an initialized Filesystem source.
func (s *Source) Init(aCtx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	s.log = aCtx.Logger()

	s.concurrency = concurrency
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify

	var conn sourcespb.Filesystem
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}
	s.paths = append(conn.Paths, conn.Directories...)
	s.skipBinaries = conn.GetSkipBinaries()
	s.followSymlinks = conn.GetFollowSymlinks()

	filter, err := common.FilterFromFiles(conn.IncludePathsFile, conn.ExcludePathsFile)
	if err != nil {
		return fmt.Errorf("unable to create filter: %w", err)
	}
	s.filter = filter

	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	for i, path := range s.paths {
		logger := ctx.Logger().WithValues("path", path)
		if common.IsDone(ctx) {
			return nil
		}
		s.SetProgressComplete(i, len(s.paths), fmt.Sprintf("Path: %s", path), "")

		// Initialize per-path tracking - critically important for memory management.
		// scanRootPaths is reset for each top-level path to track depth-1 symlinks.
		s.scanRootPaths = make(map[string]struct{})

		// Create LRU cache only if following symlinks to avoid unnecessary memory allocation.
		// The cache is recreated for each scan path to prevent memory accumulation across
		// multiple scans. This ensures O(paths_per_scan) memory instead of O(total_paths).
		if s.followSymlinks {
			// Maximum of 10k paths limits memory to ~1MB even for very large directory trees.
			// If a directory has >10k symlinks, oldest entries are evicted (LRU behavior).
			const maxCacheSize = 10000
			cache, err := lru.NewCache[struct{}]("filesystem_visited", lru.WithCapacity[struct{}](maxCacheSize))
			if err != nil {
				logger.Error(err, "failed to create LRU cache for symlink tracking")
				continue
			}
			s.visitedPaths = cache
		}

		cleanPath := filepath.Clean(path)

		// Store the scan root path for depth tracking
		s.scanRootPaths[cleanPath] = struct{}{}

		var fileInfo fs.FileInfo
		var err error
		if s.followSymlinks {
			fileInfo, err = os.Stat(cleanPath)
		} else {
			fileInfo, err = os.Lstat(cleanPath)
		}
		if err != nil {
			logger.Error(err, "unable to get file info")
			continue
		}

		if !s.followSymlinks && fileInfo.Mode()&os.ModeSymlink != 0 {
			logger.Info("skipping, not a regular file", "path", cleanPath)
			continue
		}

		// If followSymlinks is enabled and this is a symlink, check for loops
		if s.followSymlinks && fileInfo.Mode()&os.ModeSymlink != 0 {
			canonicalPath, err := filepath.EvalSymlinks(cleanPath)
			if err != nil {
				logger.V(5).Info("unable to resolve symlink", "path", cleanPath, "error", err)
				continue
			}

			// Check for loops using the LRU cache
			if s.visitedPaths.Exists(canonicalPath) {
				logger.Info("skipping symlink loop detected", "path", cleanPath, "target", canonicalPath)
				continue
			}
			s.visitedPaths.Set(canonicalPath, struct{}{})

			// Re-stat the canonical path to determine if it's a file or directory
			fileInfo, err = os.Stat(canonicalPath)
			if err != nil {
				logger.Error(err, "unable to stat symlink target")
				continue
			}
		}

		if fileInfo.IsDir() {
			err = s.scanDir(ctx, cleanPath, chunksChan)
		} else {
			err = s.scanFile(ctx, cleanPath, chunksChan)
		}

		if err != nil && !errors.Is(err, io.EOF) {
			if !errors.Is(err, skipSymlinkErr) {
				logger.Error(err, "error scanning filesystem")
			}
		}
	}

	return nil
}
func (s *Source) scanDir(ctx context.Context, path string, chunksChan chan *sources.Chunk) error {
	workerPool := new(errgroup.Group)
	workerPool.SetLimit(s.concurrency)
	defer func() {
		_ = workerPool.Wait()
		s.ClearEncodedResumeInfoFor(path)
	}()
	startState := s.GetEncodedResumeInfoFor(path)
	resuming := startState != ""

	return fs.WalkDir(os.DirFS(path), ".", func(relativePath string, d fs.DirEntry, err error) error {
		if err != nil {
			ctx.Logger().Error(err, "error walking directory")
			return nil
		}

		fullPath := filepath.Join(path, relativePath)

		// check if the full path is not matching any pattern in include FilterRuleSet and matching any exclude FilterRuleSet.
		if s.filter != nil && !s.filter.Pass(fullPath) {
			// skip excluded directories
			if d.IsDir() && s.filter.ShouldExclude(fullPath) {
				return fs.SkipDir
			}

			return nil // skip the file
		}

		// Handle symlinks when followSymlinks is enabled.
		// DEPTH-1 ENFORCEMENT: Only follow symlinks that are direct children of scan root paths.
		// This prevents:
		// 1. Infinite symlink chains (A->B->C->...)
		// 2. Deep directory traversal through symlinks
		//
		// Example: If scanning /path/to/dir:
		//   - /path/to/dir/link.txt (direct child) -> WILL be followed
		//   - /path/to/dir/subdir/link.txt (not direct child) -> will NOT be followed
		if s.followSymlinks && d.Type()&fs.ModeSymlink != 0 {
			// Only follow symlinks that are direct children of the scan root
			if !s.isDirectChild(fullPath) {
				ctx.Logger().V(5).Info("skipping symlink (not a direct child of scan root)", "path", fullPath)
				return nil
			}

			// Resolve the symlink to its canonical path for loop detection.
			// This handles cases where multiple symlinks point to the same file.
			canonicalPath, err := filepath.EvalSymlinks(fullPath)
			if err != nil {
				// Broken symlink or permission issue, skip it
				ctx.Logger().V(5).Info("unable to resolve symlink", "path", fullPath, "error", err)
				return nil
			}

			// Check for loops using LRU cache.
			// Prevents scanning the same file multiple times if reachable via different symlinks.
			// Also prevents infinite loops where symlinks form cycles.
			if s.followSymlinks && s.visitedPaths != nil && s.visitedPaths.Exists(canonicalPath) {
				ctx.Logger().Info("skipping symlink loop detected", "path", fullPath, "target", canonicalPath)
				return nil
			}
			if s.followSymlinks && s.visitedPaths != nil {
				s.visitedPaths.Set(canonicalPath, struct{}{})
			}

			// Follow the symlink to see what it points to
			targetInfo, err := os.Stat(fullPath)
			if err != nil {
				// Broken symlink or permission issue, skip it
				ctx.Logger().V(5).Info("unable to follow symlink", "path", fullPath, "error", err)
				return nil
			}
			// If the symlink points to a regular file, process it
			if targetInfo.Mode().IsRegular() {
				workerPool.Go(func() error {
					if err := s.scanFile(ctx, fullPath, chunksChan); err != nil {
						ctx.Logger().Error(err, "error scanning file", "path", fullPath, "error", err)
					}
					s.SetEncodedResumeInfoFor(path, fullPath)
					return nil
				})
			}
			return nil
		}

		// Skip over non-regular files. We do this check here to suppress noisy
		// logs for trying to scan directories and other non-regular files in
		// our traversal.
		if !d.Type().IsRegular() {
			return nil
		}

		if resuming {
			// The start state holds the path that last completed
			// scanning. When we find it, we can start scanning
			// again on the next one.
			if fullPath == startState {
				resuming = false
			}
			return nil
		}

		workerPool.Go(func() error {
			if err = s.scanFile(ctx, fullPath, chunksChan); err != nil {
				ctx.Logger().Error(err, "error scanning file", "path", fullPath, "error", err)
			}
			s.SetEncodedResumeInfoFor(path, fullPath)
			return nil
		})

		return nil
	})
}

var skipSymlinkErr = errors.New("skipping symlink")

// isDirectChild checks if a path is a direct child of any scan root path.
// This enforces depth-1 symlink following to prevent:
// - Infinite symlink loops
// - Deep directory traversal through symlinks
//
// Returns true only if the symlink's parent directory matches a scan root path.
func (s *Source) isDirectChild(path string) bool {
	dir := filepath.Clean(filepath.Dir(path))
	_, isRoot := s.scanRootPaths[dir]
	return isRoot
}

func (s *Source) scanFile(ctx context.Context, path string, chunksChan chan *sources.Chunk) error {
	fileCtx := context.WithValues(ctx, "path", path)
	var fileStat fs.FileInfo
	var err error
	if s.followSymlinks {
		fileStat, err = os.Stat(path)
	} else {
		fileStat, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("unable to stat file: %w", err)
	}
	if !s.followSymlinks && fileStat.Mode()&os.ModeSymlink != 0 {
		return skipSymlinkErr
	}

	// Check if file is binary and should be skipped
	if (s.skipBinaries || feature.ForceSkipBinaries.Load()) && common.IsBinary(path) {
		fileCtx.Logger().V(5).Info("skipping binary file", "path", path)
		return nil
	}

	inputFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open file: %w", err)
	}
	defer inputFile.Close()

	fileCtx.Logger().V(3).Info("scanning file")

	chunkSkel := &sources.Chunk{
		SourceType: s.Type(),
		SourceName: s.name,
		SourceID:   s.SourceID(),
		JobID:      s.JobID(),
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Filesystem{
				Filesystem: &source_metadatapb.Filesystem{
					File: sanitizer.UTF8(path),
				},
			},
		},
		Verify: s.verify,
	}

	return handlers.HandleFile(fileCtx, inputFile, chunkSkel, sources.ChanReporter{Ch: chunksChan})
}

// Enumerate implements SourceUnitEnumerator interface. This implementation simply
// passes the configured paths as the source unit, whether it be a single
// filepath or a directory.
func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	for _, path := range s.paths {
		_, err := os.Lstat(filepath.Clean(path))
		if err != nil {
			if err := reporter.UnitErr(ctx, err); err != nil {
				return err
			}
			continue
		}
		item := sources.CommonSourceUnit{ID: path}
		if err := reporter.UnitOk(ctx, item); err != nil {
			return err
		}
	}
	return nil
}

// ChunkUnit implements SourceUnitChunker interface.
func (s *Source) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	path, _ := unit.SourceUnitID()
	logger := ctx.Logger().WithValues("path", path)

	// Initialize per-unit tracking - same rationale as Chunks() method.
	// Each ChunkUnit call gets fresh tracking to prevent memory accumulation.
	s.scanRootPaths = make(map[string]struct{})

	// Create LRU cache only if following symlinks.
	// Memory is bounded to 10k paths (~1MB) per unit scan.
	if s.followSymlinks {
		const maxCacheSize = 10000
		cache, err := lru.NewCache[struct{}]("filesystem_visited", lru.WithCapacity[struct{}](maxCacheSize))
		if err != nil {
			return reporter.ChunkErr(ctx, fmt.Errorf("failed to create LRU cache: %w", err))
		}
		s.visitedPaths = cache
	}

	cleanPath := filepath.Clean(path)

	// Store the scan root path for depth tracking
	s.scanRootPaths[cleanPath] = struct{}{}

	var fileInfo fs.FileInfo
	var err error
	if s.followSymlinks {
		fileInfo, err = os.Stat(cleanPath)
	} else {
		fileInfo, err = os.Lstat(cleanPath)
	}
	if err != nil {
		return reporter.ChunkErr(ctx, fmt.Errorf("unable to get file info: %w", err))
	}

	// If followSymlinks is enabled and this is a symlink, check for loops
	if s.followSymlinks && fileInfo.Mode()&os.ModeSymlink != 0 {
		canonicalPath, err := filepath.EvalSymlinks(cleanPath)
		if err != nil {
			logger.V(5).Info("unable to resolve symlink", "path", cleanPath, "error", err)
			return reporter.ChunkErr(ctx, fmt.Errorf("unable to resolve symlink: %w", err))
		}

		// Check for loops
		if s.visitedPaths.Exists(canonicalPath) {
			logger.Info("skipping symlink loop detected", "path", cleanPath, "target", canonicalPath)
			return nil
		}
		s.visitedPaths.Set(canonicalPath, struct{}{})

		// Re-stat the canonical path to determine if it's a file or directory
		fileInfo, err = os.Stat(canonicalPath)
		if err != nil {
			return reporter.ChunkErr(ctx, fmt.Errorf("unable to stat symlink target: %w", err))
		}
	}

	ch := make(chan *sources.Chunk)
	var scanErr error
	go func() {
		defer close(ch)
		if fileInfo.IsDir() {
			// TODO: Finer grain error tracking of individual chunks.
			scanErr = s.scanDir(ctx, cleanPath, ch)
		} else {
			// TODO: Finer grain error tracking of individual
			// chunks (in the case of archives).
			scanErr = s.scanFile(ctx, cleanPath, ch)
		}
	}()

	for chunk := range ch {
		if chunk == nil {
			continue
		}
		if err := reporter.ChunkOk(ctx, *chunk); err != nil {
			return err
		}
	}

	if scanErr != nil && !errors.Is(scanErr, io.EOF) {
		if !errors.Is(scanErr, skipSymlinkErr) {
			logger.Error(scanErr, "error scanning filesystem")
		}
		return reporter.ChunkErr(ctx, scanErr)
	}
	return nil
}
