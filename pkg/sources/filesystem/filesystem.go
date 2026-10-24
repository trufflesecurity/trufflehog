package filesystem

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-errors/errors"
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
	filter       *common.Filter
	skipBinaries bool
	sources.Progress
	sources.CommonSourceUnitUnmarshaller
	maxSymlinkDepth int
}

// Ensure the Source satisfies the interfaces at compile time
var (
	_ sources.Source                 = (*Source)(nil)
	_ sources.SourceUnitUnmarshaller = (*Source)(nil)
	_ sources.SourceUnitEnumChunker  = (*Source)(nil)
)

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

	aCtx.Logger().V(1).Info("filesystem source initialized",
		"path_count", len(s.paths),
		"skip_binaries", s.skipBinaries,
		"max_symlink_depth", s.maxSymlinkDepth,
		"include_paths_file", conn.IncludePathsFile,
		"exclude_paths_file", conn.ExcludePathsFile,
	)
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
		if common.IsDone(ctx) {
			return nil
		}
		s.SetProgressComplete(i, len(s.paths), fmt.Sprintf("Path: %s", rootPath), s.GetProgress().EncodedResumeInfo)

		// root_path is kept apart from path, which the lines below use for the item being scanned.
		pathCtx := trContext.WithValues(ctx, "root_path", rootPath)
		fileInfo, err := os.Lstat(filepath.Clean(rootPath))
		if err != nil {
			pathCtx.Logger().Error(err, "unable to get file info")
			continue
		}

		if err := s.scanRootPath(pathCtx, chunksChan, rootPath, fileInfo); err != nil && !errors.Is(err, io.EOF) {
			pathCtx.Logger().Error(err, "error scanning filesystem")
		}
	}

	return nil
}

// scanRootPath scans one configured path, which can be a symlink, a directory, or a file.
// It is shared by Chunks and ChunkUnit so both scan and log a root path the same way.
func (s *Source) scanRootPath(
	ctx trContext.Context,
	chunksChan chan *sources.Chunk,
	rootPath string,
	fileInfo os.FileInfo,
) error {
	cleanPath := filepath.Clean(rootPath)
	initialDepth := 0
	start := time.Now()

	var err error
	switch {
	case fileInfo.Mode()&os.ModeSymlink != 0:
		ctx.Logger().V(2).Info("scanning path", "type", "symlink")
		err = s.scanSymlink(ctx, chunksChan, rootPath, initialDepth, cleanPath)
		s.ClearEncodedResumeInfoFor(rootPath)
	case fileInfo.IsDir():
		ctx.Logger().V(2).Info("scanning path", "type", "dir")
		err = s.scanDir(ctx, chunksChan, rootPath, initialDepth, cleanPath)
		s.ClearEncodedResumeInfoFor(rootPath)
	case !fileInfo.Mode().IsRegular():
		// The user asked for this path, so tell them it was not scanned.
		ctx.Logger().Info("skipping file", "reason", "not a regular file")
		return nil
	default:
		ctx.Logger().V(2).Info("scanning path", "type", "file")
		// TODO: Finer grain error tracking of individual chunks (in the case of archives).
		err = s.scanFile(ctx, chunksChan, cleanPath)
	}

	ctx.Logger().V(2).Info("finished scanning path", "duration", time.Since(start).String())
	return err
}

func (s *Source) scanSymlink(
	ctx trContext.Context,
	chunksChan chan *sources.Chunk,
	rootPath string,
	depth int,
	path string,
) error {
	if !s.canFollowSymlinks() {
		// Symlinks are only followed when a max symlink depth is set.
		ctx.Logger().V(4).Info("skipping symlink", "path", path, "reason", "following symlinks is not enabled")
		return nil
	}

	depth++

	if depth > s.maxSymlinkDepth {
		return errors.New("max symlink depth reached")
	}

	cleanPath := filepath.Clean(path)

	resolvedPath, err := os.Readlink(cleanPath)
	if err != nil {
		return fmt.Errorf("readlink error: %w", err)
	}
	if !filepath.IsAbs(resolvedPath) {
		resolvedPath = filepath.Join(filepath.Dir(cleanPath), resolvedPath)
	}
	fileInfo, err := os.Lstat(resolvedPath)
	if err != nil {
		return fmt.Errorf("lstat error: %w", err)
	}

	targetType := "other"
	switch {
	case fileInfo.Mode()&os.ModeSymlink != 0:
		targetType = "symlink"
	case fileInfo.IsDir():
		targetType = "dir"
	case fileInfo.Mode().IsRegular():
		targetType = "file"
	}
	ctx.Logger().V(5).Info("resolved symlink",
		"path", cleanPath,
		"resolved_path", resolvedPath,
		"target_type", targetType,
		"depth", depth,
	)

	switch targetType {
	case "symlink":
		return s.scanSymlink(ctx, chunksChan, rootPath, depth, resolvedPath)
	case "dir":
		return s.scanDir(ctx, chunksChan, rootPath, depth, resolvedPath)
	}

	if s.filter != nil && !s.filter.Pass(resolvedPath) {
		ctx.Logger().V(4).Info("skipping file", "path", resolvedPath, "reason", "excluded by path filter")
		return nil
	}

	// Use a single resumption key for the entire scan rooted at rootPath.
	// Resume checks are handled by the calling scanDir function.
	resumptionKey := rootPath

	if !fileInfo.Mode().Type().IsRegular() {
		ctx.Logger().V(4).Info("skipping file", "path", resolvedPath, "reason", "not a regular file")
		return nil
	}
	if err := s.scanFile(ctx, chunksChan, resolvedPath); err != nil {
		ctx.Logger().Error(err, "error scanning file", "path", resolvedPath)
	}
	s.SetEncodedResumeInfoFor(resumptionKey, cleanPath)
	return nil
}

// comparePathsForResume orders two cleaned paths the way a depth-first walk over
// os.ReadDir-sorted entries does: component by component. A raw string comparison
// is wrong here because the separator '/' (0x2F) sorts after characters that are
// valid in a path component, such as '-' (0x2D) or '.' (0x2E). For example, as raw
// strings "/root/blue-team-deprecated" < "/root/blue-team/file.txt" (the '-' after
// "blue-team" sorts before '/'), which would make scanDir wrongly skip the sibling
// directory "blue-team-deprecated" when resuming inside "blue-team". Comparing per
// component matches os.ReadDir's ordering, where "blue-team" sorts before
// "blue-team-deprecated". Returns -1, 0, or 1.
func comparePathsForResume(a, b string) int {
	// slices.Compare walks the components lexicographically and, when one path is
	// a prefix of the other, orders the shorter (ancestor) path first — matching
	// the depth-first walk order described above.
	return slices.Compare(
		strings.Split(a, string(filepath.Separator)),
		strings.Split(b, string(filepath.Separator)),
	)
}

func (s *Source) scanDir(
	ctx trContext.Context,
	chunksChan chan *sources.Chunk,
	rootPath string,
	depth int,
	path string,
) error {
	// check if the full path is not matching any pattern in include
	// FilterRuleSet and matching any exclude FilterRuleSet.
	if s.filter != nil && s.filter.ShouldExclude(path) {
		ctx.Logger().V(4).Info("skipping directory", "path", path, "reason", "excluded by path filter")
		return nil
	}

	// Use a single resumption key for the entire scan rooted at rootPath.
	// The value stored is the full path of the last successfully scanned file.
	// This avoids accumulating separate entries for each subdirectory visited.
	resumptionKey := rootPath
	resumeAfter := s.GetEncodedResumeInfoFor(resumptionKey)

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
		if comparePathsForResume(path, resumeAfter) < 0 {
			// This directory comes before the resume point in traversal order,
			// meaning it was already fully scanned. Skip it entirely.
			ctx.Logger().V(4).Info("skipping directory",
				"path", path,
				"reason", "already scanned before resume point",
				"resume_after", resumeAfter,
			)
			return nil
		}
		// This directory comes after the resume point, so we've already passed
		// the resume point. Process this directory normally.
		resumeAfter = ""
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("readdir error: %w", err)
	}
	ctx.Logger().V(3).Info("scanning directory", "path", path, "entry_count", len(entries))
	if resumeAfter != "" {
		// Entries up to the resume point are skipped without a line each, so log the resume point once.
		ctx.Logger().V(4).Info("resuming scan in directory", "path", path, "resume_after", resumeAfter)
	}

	workerPool := new(errgroup.Group)
	workerPool.SetLimit(s.concurrency)

	for _, entry := range entries {
		entryPath := filepath.Join(path, entry.Name())
		// Directories and symlinks are not skipped here because a path below them can still pass the filter.
		if s.filter != nil && !s.filter.Pass(entryPath) {
			if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
				ctx.Logger().V(4).Info("skipping file", "path", entryPath, "reason", "excluded by path filter")
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
				ctx.Logger().V(4).Info("found resume point, continuing scan after it", "path", entryPath)
				resumeAfter = ""
				continue // Skip the resume point itself since it was already processed.
			}
			// If the resume point is within this entry (a descendant), we need to
			// traverse into it to find where to resume.
			if entry.IsDir() && strings.HasPrefix(resumeAfter, entryPath+string(filepath.Separator)) {
				// Recurse into this directory to find the resume point.
				if err := s.scanDir(ctx, chunksChan, rootPath, depth, entryPath); err != nil {
					ctx.Logger().Error(err, "error scanning directory", "path", entryPath)
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
			if err := s.scanSymlink(ctx, chunksChan, rootPath, depth, entryPath); err != nil {
				ctx.Logger().Error(err, "error scanning symlink", "path", entryPath)
			}
		} else if entry.IsDir() {
			if err := s.scanDir(ctx, chunksChan, rootPath, depth, entryPath); err != nil {
				ctx.Logger().Error(err, "error scanning directory", "path", entryPath)
			}
		} else {
			if !entry.Type().IsRegular() {
				ctx.Logger().V(4).Info("skipping file", "path", entryPath, "reason", "not a regular file")
				continue
			}
			workerPool.Go(func() error {
				if err := s.scanFile(ctx, chunksChan, entryPath); err != nil {
					ctx.Logger().Error(err, "error scanning file", "path", entryPath)
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
	fileCtx := trContext.WithValues(ctx, "path", path)

	fileInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("unable to stat file: %w", err)
	}

	// Check if file is binary and should be skipped
	if (s.skipBinaries || feature.ForceSkipBinaries.Load()) && common.IsBinary(path) {
		fileCtx.Logger().V(4).Info("skipping file", "reason", "binary files are skipped")
		return nil
	}

	inputFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open file: %w", err)
	}
	defer func() { _ = inputFile.Close() }()

	fileCtx.Logger().V(3).Info("scanning file", "size", fileInfo.Size())
	start := time.Now()

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

	err = handlers.HandleFile(fileCtx, inputFile, chunkSkel, sources.ChanReporter{Ch: chunksChan})
	fileCtx.Logger().V(5).Info("finished scanning file", "duration", time.Since(start).String())
	return err
}

// Enumerate implements SourceUnitEnumerator interface. This implementation simply
// passes the configured paths as the source unit, whether it be a single
// filepath or a directory.
func (s *Source) Enumerate(ctx trContext.Context, reporter sources.UnitReporter) error {
	for _, rootPath := range s.paths {
		_, err := os.Lstat(filepath.Clean(rootPath))
		if err != nil {
			if err := reporter.UnitErr(ctx, err); err != nil {
				return err
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
	ctx = trContext.WithValues(ctx, "root_path", rootPath)

	// This will always be the FileInfo we use to decide dir vs file
	fileInfo, err := os.Lstat(filepath.Clean(rootPath))
	if err != nil {
		return reporter.ChunkErr(ctx, fmt.Errorf("unable to get file info: %w", err))
	}

	ch := make(chan *sources.Chunk)
	var scanErr error
	go func() {
		defer close(ch)
		// TODO: Finer grain error tracking of individual chunks.
		scanErr = s.scanRootPath(ctx, ch, rootPath, fileInfo)
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
