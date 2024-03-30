package filesystem

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM

type Source struct {
	name        string
	sourceId    sources.SourceID
	jobId       sources.JobID
	concurrency int
	verify      bool
	paths       []string
	log         logr.Logger
	filter      *common.Filter
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

		cleanPath := filepath.Clean(path)
		fileInfo, err := os.Lstat(cleanPath)
		if err != nil {
			logger.Error(err, "unable to get file info")
			continue
		}

		if fileInfo.Mode()&os.ModeSymlink != 0 {
			logger.Info("skipping, not a regular file", "path", cleanPath)
			continue
		}

		if fileInfo.IsDir() {
			err = s.scanDir(ctx, cleanPath, chunksChan)
		} else {
			err = s.scanFile(ctx, cleanPath, chunksChan)
		}

		if err != nil && !errors.Is(err, io.EOF) {
			logger.Info("error scanning filesystem", "error", err)
		}
	}

	return nil
}
func (s *Source) scanDir(ctx context.Context, path string, chunksChan chan *sources.Chunk) error {
	workerPool := new(errgroup.Group)
	workerPool.SetLimit(s.concurrency)
	defer func() { _ = workerPool.Wait() }()

	return fs.WalkDir(os.DirFS(path), ".", func(relativePath string, d fs.DirEntry, err error) error {
		if err != nil {
			ctx.Logger().Error(err, "error walking directory")
			return nil
		}
		fullPath := filepath.Join(path, relativePath)

		// Skip over non-regular files. We do this check here to suppress noisy
		// logs for trying to scan directories and other non-regular files in
		// our traversal.
		if !d.Type().IsRegular() {
			return nil
		}
		if s.filter != nil && !s.filter.Pass(fullPath) {
			return nil
		}

		workerPool.Go(func() error {
			if err = s.scanFile(ctx, fullPath, chunksChan); err != nil {
				ctx.Logger().Error(err, "error scanning file", "path", fullPath, "error", err)
			}
			return nil
		})

		return nil
	})
}

func (s *Source) scanFile(ctx context.Context, path string, chunksChan chan *sources.Chunk) error {
	logger := ctx.Logger().WithValues("path", path)
	fileStat, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("unable to stat file: %w", err)
	}
	if fileStat.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("skipping symlink")
	}

	inputFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open file: %w", err)
	}

	bufferName := cleantemp.MkFilename()

	defer inputFile.Close()
	logger.V(3).Info("scanning file")

	reReader, err := diskbufferreader.New(inputFile, diskbufferreader.WithBufferName(bufferName))
	if err != nil {
		return fmt.Errorf("could not create re-readable reader: %w", err)
	}
	defer reReader.Close()

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
	if handlers.HandleFile(ctx, reReader, chunkSkel, sources.ChanReporter{Ch: chunksChan}) {
		return nil
	}

	if err := reReader.Reset(); err != nil {
		return err
	}
	reReader.Stop()

	chunkReader := sources.NewChunkReader()
	chunkResChan := chunkReader(ctx, reReader)
	for data := range chunkResChan {
		if err := data.Error(); err != nil {
			s.log.Error(err, "error reading chunk.")
			continue
		}

		chunk := &sources.Chunk{
			SourceType: s.Type(),
			SourceName: s.name,
			SourceID:   s.SourceID(),
			JobID:      s.JobID(),
			Data:       data.Bytes(),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Filesystem{
					Filesystem: &source_metadatapb.Filesystem{
						File: sanitizer.UTF8(path),
					},
				},
			},
			Verify: s.verify,
		}
		if err := common.CancellableWrite(ctx, chunksChan, chunk); err != nil {
			return err
		}
	}

	return nil
}

// Enumerate implements SourceUnitEnumerator interface. This implementation simply
// passes the configured paths as the source unit, whether it be a single
// filepath or a directory.
func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	for _, path := range s.paths {
		fileInfo, err := os.Lstat(filepath.Clean(path))
		if err != nil {
			if err := reporter.UnitErr(ctx, err); err != nil {
				return err
			}
			continue
		}
		if !fileInfo.IsDir() {
			item := sources.CommonSourceUnit{ID: path}
			if err := reporter.UnitOk(ctx, item); err != nil {
				return err
			}
			continue
		}
		err = fs.WalkDir(os.DirFS(path), ".", func(relativePath string, d fs.DirEntry, err error) error {
			if err != nil {
				return reporter.UnitErr(ctx, err)
			}
			if d.IsDir() {
				return nil
			}
			fullPath := filepath.Join(path, relativePath)
			if s.filter != nil && !s.filter.Pass(fullPath) {
				return nil
			}
			item := sources.CommonSourceUnit{ID: fullPath}
			return reporter.UnitOk(ctx, item)
		})
		if err != nil {
			if err := reporter.UnitErr(ctx, err); err != nil {
				return err
			}
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

	if scanErr != nil && scanErr != io.EOF {
		logger.Info("error scanning filesystem", "error", scanErr)
		return reporter.ChunkErr(ctx, scanErr)
	}
	return nil
}
