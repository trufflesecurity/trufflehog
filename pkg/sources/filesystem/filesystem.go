package filesystem

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

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
	name         string
	sourceId     sources.SourceID
	jobId        sources.JobID
	concurrency  int
	verify       bool
	paths        []string
	log          logr.Logger
	filter       *common.Filter
	skipBinaries bool
	sources.Progress
	sources.CommonSourceUnitUnmarshaller
	followSymlinks      bool
	maxSymlinkDepth     int
	visitedSymlinkPaths map[string]struct{}
	visitedmu           sync.Mutex
}

// Ensure the Source satisfies the interfaces at compile time
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)
var _ sources.SourceUnitEnumChunker = (*Source)(nil)

// max symlink depth allowed
const DEFAULT_MAX_SYMLINK_DEPTH_ALLOWED = 40

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

	filter, err := common.FilterFromFiles(conn.IncludePathsFile, conn.ExcludePathsFile)
	if err != nil {
		return fmt.Errorf("unable to create filter: %w", err)
	}
	s.filter = filter
	s.maxSymlinkDepth = int(conn.GetMaxSymlinkDepth())
	if s.maxSymlinkDepth > DEFAULT_MAX_SYMLINK_DEPTH_ALLOWED {
		err := fmt.Errorf("Specified symlink depth %v exceeds the allowed max allowed symlink depth of %v", s.maxSymlinkDepth, DEFAULT_MAX_SYMLINK_DEPTH_ALLOWED)
		return err
	}
	if s.maxSymlinkDepth > 0 {
		s.followSymlinks = true
	}
	s.visitedSymlinkPaths = make(map[string]struct{})

	return nil
}

func (s *Source) resolveSymLink(ctx context.Context, symlinkPath string) (os.FileInfo, string, error) {
	var fileInfo os.FileInfo
	var err error
	resolvedPath := symlinkPath
	var resolvedFilePath string
	for depth := 0; depth < s.maxSymlinkDepth; depth++ {
		resolvedFilePath, err = os.Readlink(resolvedPath)
		if err != nil {
			return nil, "", fmt.Errorf("Error in resolving symlink: %v", err)
		}
		if !filepath.IsAbs(resolvedFilePath) {
			resolvedFilePath = filepath.Join(
				filepath.Dir(resolvedPath),
				resolvedFilePath,
			)
		}
		fileInfo, err = os.Lstat(resolvedFilePath)
		if err != nil {
			return nil, "", fmt.Errorf("Error in retrieving info: %v", err)
		}
		if fileInfo.Mode()&os.ModeSymlink == 0 {
			ctx.Logger().V(5).Info("Symlink has been resolved", "symlinkPath", symlinkPath, "resolvedPath", resolvedFilePath, "depth", depth+1)
			return fileInfo, filepath.Clean(resolvedFilePath), nil
		}
		resolvedPath = filepath.Clean(resolvedFilePath)
	}
	return nil, "", fmt.Errorf("Unable to resolve symlink %s for the specified depth %d", symlinkPath, s.maxSymlinkDepth)
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	for i, path := range s.paths {
		logger := ctx.Logger().WithValues("path", path)
		if common.IsDone(ctx) {
			return nil
		}
		s.SetProgressComplete(i, len(s.paths), fmt.Sprintf("Path: %s", path), "")

		cleanPath := filepath.Clean(path)
		fileInfo, err := os.Lstat(cleanPath)
		if err != nil {
			logger.Error(err, "unable to get file info")
			continue
		}

		// This will always be the FileInfo we use to decide dir vs file
		targetInfo := fileInfo
		targetInfoPath := cleanPath

		if fileInfo.Mode()&os.ModeSymlink != 0 {
			if !s.followSymlinks {
				// If the file or directory is a symlink but the followSymlinks is disable ignore the path
				logger.Info("skipping, following symlinks is not allowed", "path", cleanPath)
				continue
			}
			// if the root path is a symlink resolve the path and check if it resolves to a dir or file
			// if targetInfo is a dir then call scanDir otherwise call scanFile
			targetInfo, targetInfoPath, err = s.resolveSymLink(ctx, cleanPath)
			if err != nil {
				logger.Error(err, err.Error())
				continue
			}
		}

		if targetInfo.IsDir() {
			workerPool := new(errgroup.Group)
			workerPool.SetLimit(s.concurrency)
			err = s.scanDir(ctx, targetInfoPath, chunksChan, workerPool)
			_ = workerPool.Wait()
			s.ClearEncodedResumeInfoFor(path)
		} else {
			err = s.scanFile(ctx, targetInfoPath, chunksChan)
		}

		if err != nil && !errors.Is(err, io.EOF) {
			if !errors.Is(err, skipSymlinkErr) {
				logger.Error(err, "error scanning filesystem")
			}
		}
	}

	return nil
}

func (s *Source) checkVisitedSymlink(resolvedpath string) bool {
	cleanedPath := filepath.Clean(resolvedpath)
	s.visitedmu.Lock()
	defer s.visitedmu.Unlock()

	if _, seen := s.visitedSymlinkPaths[cleanedPath]; seen {
		return true
	}
	return false
}
func (s *Source) markVisitedPath(resolvedpath string) {
	cleanedPath := filepath.Clean(resolvedpath)
	s.visitedmu.Lock()
	defer s.visitedmu.Unlock()
	s.visitedSymlinkPaths[cleanedPath] = struct{}{}
}

func (s *Source) scanDir(ctx context.Context, path string, chunksChan chan *sources.Chunk, workerPool *errgroup.Group) error {
	startState := s.GetEncodedResumeInfoFor(path)
	resuming := startState != ""
	s.markVisitedPath(path)
	return fs.WalkDir(os.DirFS(path), ".", func(relativePath string, d fs.DirEntry, err error) error {
		if err != nil {
			ctx.Logger().Error(err, "error walking directory")
			return nil
		}

		fullPath := filepath.Join(path, relativePath)
		ctx.Logger().V(5).Info("Full path found is", "fullPath", fullPath)

		// check if the full path is not matching any pattern in include FilterRuleSet and matching any exclude FilterRuleSet.
		if s.filter != nil && !s.filter.Pass(fullPath) {
			// skip excluded directories
			if d.IsDir() && s.filter.ShouldExclude(fullPath) {
				return fs.SkipDir
			}

			return nil // skip the file
		}

		if d.Type()&os.ModeSymlink != 0 {
			if s.followSymlinks {
				ctx.Logger().V(5).Info("Directory/File found is a symlink", "path", path)
				// if the found directory or file is symlink resolve the symlink
				resolved, resolvedPath, err := s.resolveSymLink(ctx, fullPath)
				if err != nil {
					ctx.Logger().Error(err, err.Error(), "path", fullPath)
					return nil
				}
				// If symlink resolves to a file then scan it
				if !resolved.IsDir() {
					ctx.Logger().V(5).Info("Resolved symlink is a file", "path", resolvedPath)
					if resuming {
						// Since we store the resolved file path in encodeResumeInfo
						// so we match the resolved with startState
						if resolvedPath == startState {
							resuming = false
						}
						return nil
					}
					workerPool.Go(func() error {
						if err := s.scanFile(ctx, resolvedPath, chunksChan); err != nil {
							ctx.Logger().Error(err, "error scanning file", "path", resolvedPath)
						}
						s.SetEncodedResumeInfoFor(path, resolvedPath)
						return nil
					})
					return nil
				}
				// This check is to avoid loopy scenarios like A/linkToB->B and B/linkToA->A
				// We are going to maintain the map of symlinks resolved to a directory
				// as this case won't happen in symlinks resolved to file
				if s.checkVisitedSymlink(resolvedPath) {
					ctx.Logger().V(5).Info("Resolved path is already visited", "path", resolvedPath)
					return nil
				}
				// If symlink resolves to directory scan that directory
				ctx.Logger().V(5).Info("Resolved symlink is a directory", "path", resolvedPath)
				err = s.scanDir(ctx, resolvedPath, chunksChan, workerPool)
				if err != nil {
					ctx.Logger().Error(err, "error occurred in nested recursive scanDir call")
				}
				return nil
			}
			// Skip symlinks if followSymlinks is false
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

func (s *Source) scanFile(ctx context.Context, path string, chunksChan chan *sources.Chunk) error {
	fileCtx := context.WithValues(ctx, "path", path)
	fileStat, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("unable to stat file: %w", err)
	}
	if fileStat.Mode()&os.ModeSymlink != 0 {
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

	cleanPath := filepath.Clean(path)
	fileInfo, err := os.Lstat(cleanPath)
	if err != nil {
		return reporter.ChunkErr(ctx, fmt.Errorf("unable to get file info: %w", err))
	}
	// This will always be the FileInfo we use to decide dir vs file
	targetInfo := fileInfo
	targetInfoPath := cleanPath
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		if !s.followSymlinks {
			// If the file or directory is a symlink but the followSymlinks is disable ignore the path
			logger.Info("skipping, following symlinks is not enabled", "path", cleanPath)
			return nil
		}
		// if the root path is a symlink resolve the path and check if it resolves to a dir or file
		// if resolvedSymlinkInfo is a dir then call scanDir otherwise call scanFile
		targetInfo, targetInfoPath, err = s.resolveSymLink(ctx, cleanPath)
		if err != nil {
			logger.Error(err, "unable to get symlink info")
			return nil
		}
	}

	ch := make(chan *sources.Chunk)
	var scanErr error
	go func() {
		defer close(ch)
		if targetInfo.IsDir() {
			workerPool := new(errgroup.Group)
			workerPool.SetLimit(s.concurrency)
			// TODO: Finer grain error tracking of individual chunks.
			scanErr = s.scanDir(ctx, targetInfoPath, ch, workerPool)
			_ = workerPool.Wait()
			s.ClearEncodedResumeInfoFor(path)
		} else {
			// TODO: Finer grain error tracking of individual
			// chunks (in the case of archives).
			scanErr = s.scanFile(ctx, targetInfoPath, ch)
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
