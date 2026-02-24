package filesystem

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

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
	maxSymlinkDepth int
}

// Ensure the Source satisfies the interfaces at compile time
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)
var _ sources.SourceUnitEnumChunker = (*Source)(nil)

// max symlink depth allowed
const defaultMaxSymlinkDepth = 40

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
	err = s.setMaxSymlinkDepth(&conn)
	if err != nil {
		return err
	}
	return nil
}

func (s *Source) setMaxSymlinkDepth(conn *sourcespb.Filesystem) error {
	depth := int(conn.GetMaxSymlinkDepth())
	if depth > defaultMaxSymlinkDepth {
		return fmt.Errorf(
			"specified symlink depth %d exceeds the allowed max of %d",
			depth,
			defaultMaxSymlinkDepth,
		)
	}
	s.maxSymlinkDepth = depth
	return nil
}

func (s *Source) canFollowSymlinks() bool {
	return s.maxSymlinkDepth > 0
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

		if fileInfo.Mode()&os.ModeSymlink != 0 {
			if !s.canFollowSymlinks() {
				// If the file or directory is a symlink but the followSymlinks is disable ignore the path
				logger.Info("skipping, following symlinks is not allowed", "path", cleanPath)
				continue
			}
			// if the root path is a symlink we scan the symlink
			ctx.Logger().V(5).Info("Root path is a symlink", "path", cleanPath)
			workerPool := new(errgroup.Group)
			workerPool.SetLimit(s.concurrency)
			initialDepth := 1
			err = s.scanSymlink(ctx, cleanPath, chunksChan, workerPool, initialDepth, path)
			_ = workerPool.Wait()
			s.ClearEncodedResumeContainingId(path)
		} else if fileInfo.IsDir() {
			ctx.Logger().V(5).Info("Root path is a dir", "path", cleanPath)
			workerPool := new(errgroup.Group)
			workerPool.SetLimit(s.concurrency)
			initialDepth := 1
			err = s.scanDir(ctx, cleanPath, chunksChan, workerPool, initialDepth, path)
			_ = workerPool.Wait()
			s.ClearEncodedResumeContainingId(path)
		} else {
			if !fileInfo.Mode().IsRegular() {
				logger.Info("skipping non-regular file", "path", cleanPath)
				continue
			}
			ctx.Logger().V(5).Info("Root path is a file", "path", cleanPath)
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

func (s *Source) scanSymlink(
	ctx context.Context,
	path string,
	chunksChan chan *sources.Chunk,
	workerPool *errgroup.Group,
	depth int,
	rootPath string,
) error {
	if depth > s.maxSymlinkDepth {
		return errors.New("max symlink depth reached")
	}
	path = filepath.Clean(path)

	resolvedPath, err := os.Readlink(path)
	if err != nil {
		return fmt.Errorf("readlink error: %w", err)
	}
	if !filepath.IsAbs(resolvedPath) {
		resolvedPath = filepath.Join(filepath.Dir(path), resolvedPath)
	}
	fileInfo, err := os.Lstat(resolvedPath)
	if err != nil {
		return fmt.Errorf("lstat error: %w", err)
	}

	if fileInfo.Mode()&os.ModeSymlink != 0 {
		ctx.Logger().V(5).Info(
			"found symlink to symlink",
			"symlinkPath", path,
			"resolvedPath", resolvedPath,
			"depth", depth,
		)
		return s.scanSymlink(ctx, resolvedPath, chunksChan, workerPool, depth+1, rootPath)
	}

	if fileInfo.IsDir() {
		ctx.Logger().V(5).Info(
			"found symlink to dir",
			"symlinkPath", path,
			"resolvedPath", resolvedPath,
			"depth", depth,
		)

		return s.scanDir(ctx, resolvedPath, chunksChan, workerPool, depth+1, rootPath)
	}
	ctx.Logger().V(5).Info(
		"found symlink to file",
		"symlinkPath", path,
		"resolvedPath", resolvedPath,
		"depth", depth,
	)
	if s.filter != nil && !s.filter.Pass(resolvedPath) {
		return nil
	}
	workerPool.Go(func() error {
		if !fileInfo.Mode().Type().IsRegular() {
			ctx.Logger().V(5).Info("skipping non-regular file", "path", resolvedPath)
			return nil
		}
		if err := s.scanFile(ctx, resolvedPath, chunksChan); err != nil {
			ctx.Logger().Error(err, "error scanning file", "path", resolvedPath)
		}
		return nil
	})

	return nil
}

func (s *Source) scanDir(
	ctx context.Context,
	path string,
	chunksChan chan *sources.Chunk,
	workerPool *errgroup.Group,
	depth int,
	rootPath string,
) error {
	// check if the full path is not matching any pattern in include
	// FilterRuleSet and matching any exclude FilterRuleSet.
	if s.filter != nil && s.filter.ShouldExclude(path) {
		return nil
	}
	startState := s.GetEncodedResumeInfoFor(rootPath + path)
	resuming := startState != ""

	ctx.Logger().V(5).Info("Full path found is", "fullPath", path)

	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("readdir error: %w", err)
	}

	for _, entry := range entries {
		entryPath := filepath.Join(path, entry.Name())
		if s.filter != nil && !s.filter.Pass(entryPath) {
			if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
				continue
			}
		}

		if resuming {
			if entryPath == startState {
				resuming = false
			}
		} else if entry.Type()&os.ModeSymlink != 0 {
			ctx.Logger().V(5).Info("Entry found is a symlink", "path", entryPath)
			if !s.canFollowSymlinks() {
				// If the file or directory is a symlink but the followSymlinks is disable ignore the path
				ctx.Logger().Info("skipping, following symlinks is not allowed", "path", entryPath)
				continue
			}
			if err := s.scanSymlink(ctx, entryPath, chunksChan, workerPool, depth, rootPath); err != nil {
				ctx.Logger().Error(err, "error scanning symlink", "path", entryPath)
			}
		} else if entry.IsDir() {
			ctx.Logger().V(5).Info("Entry found is a directory", "path", entryPath)
			if err := s.scanDir(ctx, entryPath, chunksChan, workerPool, depth, rootPath); err != nil {
				ctx.Logger().Error(err, "error scanning directory", "path", entryPath)
			}
		} else {
			if !entry.Type().IsRegular() {
				continue
			}
			ctx.Logger().V(5).Info("Entry found is a file", "path", entryPath)
			workerPool.Go(func() error {
				if err := s.scanFile(ctx, entryPath, chunksChan); err != nil {
					ctx.Logger().Error(err, "error scanning file", "path", entryPath)
				}
				s.SetEncodedResumeInfoFor(rootPath+path, entryPath)
				return nil
			})
		}
	}

	return nil
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

	ch := make(chan *sources.Chunk)
	var scanErr error
	go func() {
		defer close(ch)
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			if !s.canFollowSymlinks() {
				// If the file or directory is a symlink but the followSymlinks is disable ignore the path
				logger.Info("skipping, following symlinks is not allowed", "path", cleanPath)
				return
			}
			// if the root path is a symlink we scan the symlink
			ctx.Logger().V(5).Info("Root path is a symlink", "path", cleanPath)
			workerPool := new(errgroup.Group)
			workerPool.SetLimit(s.concurrency)
			initialDepth := 1
			scanErr = s.scanSymlink(ctx, cleanPath, ch, workerPool, initialDepth, path)
			_ = workerPool.Wait()
			s.ClearEncodedResumeContainingId(path)

		} else if fileInfo.IsDir() {
			ctx.Logger().V(5).Info("Root path is a dir", "path", cleanPath)
			workerPool := new(errgroup.Group)
			workerPool.SetLimit(s.concurrency)
			initialDepth := 1
			// TODO: Finer grain error tracking of individual chunks.
			scanErr = s.scanDir(ctx, cleanPath, ch, workerPool, initialDepth, path)
			_ = workerPool.Wait()
			s.ClearEncodedResumeContainingId(path)
		} else {
			ctx.Logger().V(5).Info("Root path is a file", "path", cleanPath)
			// TODO: Finer grain error tracking of individual
			// chunks (in the case of archives).
			if !fileInfo.Mode().IsRegular() {
				logger.Info("skipping non-regular file", "path", cleanPath)
				return
			}
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
