package filesystem

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	trContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
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
func (s *Source) Init(aCtx trContext.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
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
func (s *Source) Chunks(ctx trContext.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	for i, rootPath := range s.paths {
		ctx = trContext.WithValues(ctx,
			"root_path", rootPath,
		)
		if common.IsDone(ctx) {
			return nil
		}
		s.SetProgressComplete(i, len(s.paths), fmt.Sprintf("Path: %s", rootPath), "")

		cleanPath := filepath.Clean(rootPath)

		ctx = trContext.WithValues(ctx,
			"clean_path", cleanPath,
		)

		fileInfo, err := os.Lstat(cleanPath)
		if err != nil {
			ctx.Logger().Error(err, "unable to get file info")
			continue
		}

		if fileInfo.Mode()&os.ModeSymlink != 0 {
			// if the root path is a symlink we scan the symlink
			ctx.Logger().V(5).Info("Root path is a symlink")
			initialDepth := 0
			err = s.scanSymlink(ctx, chunksChan, rootPath, initialDepth, cleanPath)
			s.ClearEncodedResumeInfoFor(rootPath)
		} else if fileInfo.IsDir() {
			ctx.Logger().V(5).Info("Root path is a dir")
			initialDepth := 0
			err = s.scanDir(ctx, chunksChan, rootPath, initialDepth, cleanPath)
			s.ClearEncodedResumeInfoFor(rootPath)
		} else {
			if !fileInfo.Mode().IsRegular() {
				ctx.Logger().V(2).Info("Root path is a non-regular file; skipping")
				continue
			}
			ctx.Logger().V(5).Info("Root path is a file")
			err = s.scanFile(ctx, chunksChan, cleanPath)
		}

		if err != nil && !errors.Is(err, io.EOF) {
			ctx.Logger().Error(err, "error scanning filesystem")
		}
	}

	return nil
}

func (s *Source) scanSymlink(
	ctx trContext.Context,
	chunksChan chan *sources.Chunk,
	rootPath string,
	depth int,
	path string,
) error {
	ctx = trContext.WithValues(ctx,
		"root_path", rootPath,
		"depth", depth,
		"path", path,
	)

	ctx.Logger().V(5).Info("scanSymlink")

	if !s.canFollowSymlinks() {
		// If the file or directory is a symlink but the followSymlinks is disable ignore the path
		ctx.Logger().V(2).Info("Path is a symlink, but following symlinks is not allowed; skipping")
		return nil
	}

	depth++

	ctx = trContext.WithValues(ctx,
		"depth", depth,
	)

	if depth > s.maxSymlinkDepth {
		return fmt.Errorf("depth %d exceeds max symlink depth of %d",
			depth,
			s.maxSymlinkDepth,
		)
	}

	cleanPath := filepath.Clean(path)

	ctx = trContext.WithValues(ctx,
		"clean_path", cleanPath,
	)

	resolvedPath, err := os.Readlink(cleanPath)
	if err != nil {
		return fmt.Errorf("readlink error: %w", err)
	}

	if !filepath.IsAbs(resolvedPath) {
		resolvedPath = filepath.Join(filepath.Dir(cleanPath), resolvedPath)
	}

	ctx = trContext.WithValues(ctx,
		"resolved_path", resolvedPath,
	)

	fileInfo, err := os.Lstat(resolvedPath)
	if err != nil {
		return fmt.Errorf("lstat error: %w", err)
	}

	if fileInfo.Mode()&os.ModeSymlink != 0 {
		ctx.Logger().V(5).Info("Symlink links to another symlink")
		return s.scanSymlink(ctx, chunksChan, rootPath, depth, resolvedPath)
	}

	if fileInfo.IsDir() {
		ctx.Logger().V(5).Info("Symlink links to a directory")
		return s.scanDir(ctx, chunksChan, rootPath, depth, resolvedPath)
	}

	ctx.Logger().V(5).Info("Symlink links to a file")

	if s.filter != nil && !s.filter.Pass(resolvedPath) {
		ctx.Logger().V(2).Info("File was filtered out by filter.Pass; skipping")
		return nil
	}

	// Use a single resumption key for the entire scan rooted at rootPath.
	// Resume checks are handled by the calling scanDir function.
	resumptionKey := rootPath

	if !fileInfo.Mode().Type().IsRegular() {
		ctx.Logger().V(2).Info("File is a non-regular file; skipping")
		return nil
	}

	if err := s.scanFile(ctx, chunksChan, resolvedPath); err != nil {
		ctx.Logger().Error(err, "error scanning file")
	}

	s.SetEncodedResumeInfoFor(resumptionKey, cleanPath)

	return nil
}

func (s *Source) scanDir(
	ctx trContext.Context,
	chunksChan chan *sources.Chunk,
	rootPath string,
	depth int,
	path string,
) error {
	ctx = trContext.WithValues(ctx,
		"root_path", rootPath,
		"depth", depth,
		"path", path,
	)

	ctx.Logger().V(5).Info("scanDir")

	// check if the full path is not matching any pattern in include
	// FilterRuleSet and matching any exclude FilterRuleSet.
	if s.filter != nil && s.filter.ShouldExclude(path) {
		ctx.Logger().V(2).Info("Path was filtered out by filter.ShouldExclude; skipping")
		return nil
	}

	// Use a single resumption key for the entire scan rooted at rootPath.
	// The value stored is the full path of the last successfully scanned file.
	// This avoids accumulating separate entries for each subdirectory visited.
	resumptionKey := rootPath
	resumeAfter := s.GetEncodedResumeInfoFor(resumptionKey)

	ctx = trContext.WithValues(ctx,
		"resume_after", resumeAfter,
	)

	// Only consider resumption if the resume point is within this directory's subtree.
	// Since os.ReadDir returns entries sorted by filename:
	// - If we're scanning /root/ccc and the resume point is /root/bbb/file.txt,
	//   we've already passed it (bbb < ccc) and should process ccc normally.
	// - If we're scanning /root/aaa and the resume point is /root/bbb/file.txt,
	//   we haven't reached it yet (aaa < bbb), so aaa was already fully scanned
	//   and should be skipped entirely.
	if resumeAfter != "" && !strings.HasPrefix(resumeAfter, path+string(filepath.Separator)) && resumeAfter != path {
		// Resume point is not in this subtree. Compare paths to determine if we
		// should skip this directory (already scanned) or process it (already passed).
		if path < resumeAfter {
			ctx.Logger().V(5).Info("Resumption: path already seen")
			// This directory comes before the resume point lexicographically,
			// meaning it was already fully scanned. Skip it entirely.
			return nil
		}

		ctx.Logger().V(5).Info("Resumption: complete")
		// This directory comes after the resume point, so we've already passed
		// the resume point. Process this directory normally.
		resumeAfter = ""
		ctx = trContext.WithValues(ctx,
			"resume_after", resumeAfter,
		)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("readdir error: %w", err)
	}

	workerPool := new(errgroup.Group)
	workerPool.SetLimit(s.concurrency)

	for _, entry := range entries {
		entryPath := filepath.Join(path, entry.Name())
		ctx := trContext.WithValues(ctx,
			"entry_path", entryPath,
			"resume_after", resumeAfter,
		)

		if s.filter != nil && !s.filter.Pass(entryPath) {
			if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
				ctx.Logger().V(2).Info("File entry was filtered by filter.Pass; skipping")
				continue
			}
		}

		// Skip entries until we pass the resume point.
		// We don't clear the resume info when we find the resume point - instead we
		// keep it set until a new file is scanned. This ensures we don't lose progress
		// if the scan is interrupted between finding the resume point and scanning
		// the next file.
		if resumeAfter != "" {
			// If this entry is the resume point, stop skipping.
			if entryPath == resumeAfter {
				ctx.Logger().V(5).Info("Resumption: resume point already seen")
				resumeAfter = ""
				continue // Skip the resume point itself since it was already processed.
			}
			// If the resume point is within this entry (a descendant), we need to
			// traverse into it to find where to resume.
			if entry.IsDir() && strings.HasPrefix(resumeAfter, entryPath+string(filepath.Separator)) {
				// Recurse into this directory to find the resume point.
				if err := s.scanDir(ctx, chunksChan, rootPath, depth, entryPath); err != nil {
					ctx.Logger().Error(err, "error scanning directory")
				}
				// After recursing, clear local resumeAfter. The child scanDir will have
				// handled resumption within its subtree, and subsequent entries in this
				// directory should be processed normally.
				resumeAfter = ""
				continue
			}

			// Skip this entry - it comes before the resume point in traversal order.
			continue
		}

		if entry.Type()&os.ModeSymlink != 0 {
			ctx.Logger().V(5).Info("Entry is a symlink")
			if err := s.scanSymlink(ctx, chunksChan, rootPath, depth, entryPath); err != nil {
				ctx.Logger().Error(err, "error scanning symlink")
			}
		} else if entry.IsDir() {
			ctx.Logger().V(5).Info("Entry is a directory")
			if err := s.scanDir(ctx, chunksChan, rootPath, depth, entryPath); err != nil {
				ctx.Logger().Error(err, "error scanning directory")
			}
		} else {
			if !entry.Type().IsRegular() {
				continue
			}

			ctx.Logger().V(5).Info("Entry found is a file")
			workerPool.Go(func() error {
				if err := s.scanFile(ctx, chunksChan, entryPath); err != nil {
					ctx.Logger().Error(err, "error scanning file")
				}

				s.SetEncodedResumeInfoFor(resumptionKey, entryPath)

				return nil
			})
		}
	}

	_ = workerPool.Wait() // [TODO] Handle errors

	return nil
}

func (s *Source) scanFile(ctx trContext.Context, chunksChan chan *sources.Chunk, path string) error {
	ctx = trContext.WithValues(ctx,
		"path", path,
	)

	ctx.Logger().V(5).Info("scanFile")

	// Check if file is binary and should be skipped
	if (s.skipBinaries || feature.ForceSkipBinaries.Load()) && common.IsBinary(path) {
		ctx.Logger().V(5).Info("File is binary; skipping")
		return nil
	}

	inputFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open file: %w", err)
	}
	defer inputFile.Close()

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
		SourceVerify: s.verify,
	}

	return handlers.HandleFile(ctx, inputFile, chunkSkel, sources.ChanReporter{Ch: chunksChan})
}

// Enumerate implements SourceUnitEnumerator interface. This implementation simply
// passes the configured paths as the source unit, whether it be a single
// filepath or a directory.
func (s *Source) Enumerate(ctx trContext.Context, reporter sources.UnitReporter) error {
	for _, rootPath := range s.paths {
		ctx = trContext.WithValues(ctx,
			"root_path", rootPath,
		)

		if _, err := os.Lstat(filepath.Clean(rootPath)); err != nil {
			ctx.Logger().Error(err, "unable to stat path")

			if unitErrErr := reporter.UnitErr(ctx, err); unitErrErr != nil {
				return unitErrErr
			}

			continue
		}

		item := sources.CommonSourceUnit{ID: rootPath}
		if err := reporter.UnitOk(ctx, item); err != nil {
			return err
		}
	}

	return nil
}

// ChunkUnit implements SourceUnitChunker interface.
func (s *Source) ChunkUnit(ctx trContext.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	rootPath, _ := unit.SourceUnitID()

	ctx = trContext.WithValues(ctx,
		"root_path", rootPath,
	)

	cleanPath := filepath.Clean(rootPath)

	ctx = trContext.WithValues(ctx,
		"clean_path", cleanPath,
	)

	fileInfo, err := os.Lstat(cleanPath)
	if err != nil {
		return reporter.ChunkErr(ctx, fmt.Errorf("unable to get file info: %w", err))
	}

	ch := make(chan *sources.Chunk)
	var scanErr error
	go func() {
		defer close(ch)
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			// if the root path is a symlink we scan the symlink
			ctx.Logger().V(5).Info("Root unit is a symlink")
			initialDepth := 0
			scanErr = s.scanSymlink(ctx, ch, rootPath, initialDepth, cleanPath)
			s.ClearEncodedResumeInfoFor(rootPath)

		} else if fileInfo.IsDir() {
			ctx.Logger().V(5).Info("Root unit is a directory")
			initialDepth := 0
			// TODO: Finer grain error tracking of individual chunks.
			scanErr = s.scanDir(ctx, ch, rootPath, initialDepth, cleanPath)
			s.ClearEncodedResumeInfoFor(rootPath)
		} else {
			// TODO: Finer grain error tracking of individual
			// chunks (in the case of archives).
			if !fileInfo.Mode().IsRegular() {
				ctx.Logger().V(2).Info("Root unit is a non-regular file; skipping")
				return
			}

			ctx.Logger().V(5).Info("Root unit is a file")
			scanErr = s.scanFile(ctx, ch, cleanPath)
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
		ctx.Logger().Error(scanErr, "error scanning filesystem")
		return reporter.ChunkErr(ctx, scanErr)
	}
	return nil
}
