package handlers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mholt/archives"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

type ctxKey int

const (
	depthKey          ctxKey = iota
	defaultBufferSize        = 512
)

var (
	// NOTE: This is a temporary workaround for |openArchive| incrementing depth twice per archive.
	// See: https://github.com/trufflesecurity/trufflehog/issues/2942
	maxDepth   = 5 * 2
	maxSize    = 2 << 30 // 2 GB
	maxTimeout = time.Duration(60) * time.Second
)

// SetArchiveMaxSize sets the maximum size of the archive.
func SetArchiveMaxSize(size int) { maxSize = size }

// SetArchiveMaxDepth sets the maximum depth of the archive.
func SetArchiveMaxDepth(depth int) { maxDepth = depth }

// SetArchiveMaxTimeout sets the maximum timeout for the archive handler.
func SetArchiveMaxTimeout(timeout time.Duration) { maxTimeout = timeout }

// archiveHandler is a handler for common archive files that are supported by the archiver library.
type archiveHandler struct{ *defaultHandler }

func newArchiveHandler() *archiveHandler {
	return &archiveHandler{defaultHandler: newDefaultHandler(archiveHandlerType)}
}

// HandleFile processes archive files and returns a channel of DataOrErr.
//
// Fatal errors that will terminate processing include:
// - Context cancellation
// - Context deadline exceeded
// - Panics during archive processing (recovered and returned as fatal errors)
// - Maximum archive depth exceeded
// - Unknown archive formats
// - Errors opening decompressors
// - Errors creating readers for decompressed content
// - Errors during archive extraction
//
// Non-fatal errors that will be logged but allow processing to continue include:
// - Empty readers encountered during nested archive processing
// - Files exceeding maximum size limits
// - Files with ignored extensions or binary content
// - Errors opening individual files within archives
func (h *archiveHandler) HandleFile(ctx logContext.Context, input fileReader) chan DataOrErr {
	dataOrErrChan := make(chan DataOrErr, defaultBufferSize)

	if feature.ForceSkipArchives.Load() {
		close(dataOrErrChan)
		return dataOrErrChan
	}

	go func() {
		defer close(dataOrErrChan)

		// The underlying 7zip library may panic when attempting to open an archive.
		// This is due to an Index Out Of Range (IOOR) error when reading the archive header.
		// See: https://github.com/bodgit/sevenzip/blob/74bff0da9b233317e4ea7dd8c184a315db71af2a/types.go#L846
		defer func() {
			if r := recover(); r != nil {
				var panicErr error
				if e, ok := r.(error); ok {
					panicErr = e
				} else {
					panicErr = fmt.Errorf("panic occurred: %v", r)
				}
				dataOrErrChan <- DataOrErr{
					Err: fmt.Errorf("%w: panic error: %v", ErrProcessingFatal, panicErr),
				}
			}
		}()

		start := time.Now()
		err := h.openArchive(ctx, 0, input, dataOrErrChan)
		if err == nil {
			h.metrics.incFilesProcessed()
		}

		// Update the metrics for the file processing and handle any errors.
		h.measureLatencyAndHandleErrors(ctx, start, err, dataOrErrChan)
	}()

	return dataOrErrChan
}

var ErrMaxDepthReached = errors.New("max archive depth reached")

// openArchive recursively extracts content from an archive up to a maximum depth, handling nested archives if necessary.
// It takes a reader from which it attempts to identify and process the archive format. Depending on the archive type,
// it either decompresses or extracts the contents directly, sending data to the provided channel.
// Returns an error if the archive cannot be processed due to issues like exceeding maximum depth or unsupported formats.
func (h *archiveHandler) openArchive(
	ctx logContext.Context,
	depth int,
	reader fileReader,
	dataOrErrChan chan DataOrErr,
) error {
	ctx.Logger().V(4).Info("Starting archive processing", "depth", depth)
	defer ctx.Logger().V(4).Info("Finished archive processing", "depth", depth)

	if common.IsDone(ctx) {
		return ctx.Err()
	}

	if depth >= maxDepth {
		h.metrics.incMaxArchiveDepthCount()
		return ErrMaxDepthReached
	}

	if reader.format == nil {
		if depth > 0 {
			return h.handleNonArchiveContent(ctx, newMimeTypeReaderFromFileReader(reader), dataOrErrChan)
		}
		return fmt.Errorf("unknown archive format")
	}

	switch archive := reader.format.(type) {
	case archives.Decompressor:
		// Decompress tha archive and feed the decompressed data back into the archive handler to extract any nested archives.
		compReader, err := archive.OpenReader(reader)
		if err != nil {
			return fmt.Errorf("error opening decompressor with format: %s %w", reader.format.MediaType(), err)
		}
		defer compReader.Close()

		rdr, err := newFileReader(ctx, compReader)
		if err != nil {
			if errors.Is(err, ErrEmptyReader) {
				ctx.Logger().V(5).Info("empty reader, skipping file")
				return nil
			}
			return fmt.Errorf(
				"error creating reader for decompressor with format: %s %w",
				reader.format.MediaType(),
				err,
			)
		}
		defer rdr.Close()

		return h.openArchive(ctx, depth+1, rdr, dataOrErrChan)
	case archives.Extractor:
		err := archive.Extract(logContext.WithValue(ctx, depthKey, depth+1), reader, h.extractorHandler(dataOrErrChan))
		if err != nil {
			return fmt.Errorf("error extracting archive with format: %s: %w", reader.format.MediaType(), err)
		}
		return nil
	default:
		return fmt.Errorf("unknown archive type: %s", reader.format.MediaType())
	}
}

// extractorHandler creates a closure that handles individual files extracted by an archiver.
// It logs the extraction, checks for cancellation, and decides whether to skip the file based on its name or type,
// particularly for binary files if configured to skip. If the file is not skipped, it recursively calls openArchive
// to handle nested archives or to continue processing based on the file's content and depth in the archive structure.
func (h *archiveHandler) extractorHandler(dataOrErrChan chan DataOrErr) func(context.Context, archives.FileInfo) error {
	return func(ctx context.Context, file archives.FileInfo) error {
		if common.IsDone(ctx) {
			return ctx.Err()
		}

		lCtx := logContext.WithValues(
			logContext.AddLogger(ctx),
			"filename", file.Name(),
			"size", file.Size(),
		)

		if file.IsDir() || file.LinkTarget != "" {
			lCtx.Logger().V(4).Info("skipping directory or symlink")
			return nil
		}

		depth := 0
		if ctxDepth, ok := ctx.Value(depthKey).(int); ok {
			depth = ctxDepth
		}

		fileSize := file.Size()
		if int(fileSize) > maxSize {
			lCtx.Logger().V(2).Info("skipping file: size exceeds max allowed", "size", fileSize, "limit", maxSize)
			h.metrics.incFilesSkipped()
			return nil
		}

		if common.SkipFile(file.Name()) || common.IsBinary(file.Name()) {
			lCtx.Logger().V(4).Info("skipping file: extension is ignored")
			h.metrics.incFilesSkipped()
			return nil
		}

		f, err := file.Open()
		if err != nil {
			return fmt.Errorf("error opening file %s: %w", file.Name(), err)
		}
		defer f.Close()

		// Archiver v4 is in alpha and using an experimental version of
		// rardecode. There is a bug somewhere with rar decoder format 29
		// that can lead to a panic. An issue is open in rardecode repo
		// https://github.com/nwaples/rardecode/issues/30.
		defer func() {
			if r := recover(); r != nil {
				// Return the panic as an error.
				if e, ok := r.(error); ok {
					err = e
				} else {
					err = fmt.Errorf("panic occurred: %v", r)
				}
				lCtx.Logger().Error(err, "Panic occurred when reading archive")
			}
		}()

		rdr, err := newFileReader(ctx, f)
		if err != nil {
			if errors.Is(err, ErrEmptyReader) {
				lCtx.Logger().V(5).Info("empty reader, skipping file")
				return nil
			}
			return fmt.Errorf("error creating reader for file %s: %w", file.Name(), err)
		}
		defer rdr.Close()

		h.metrics.incFilesProcessed()
		h.metrics.observeFileSize(fileSize)

		lCtx.Logger().V(4).Info("Opened file successfully", "filename", file.Name(), "size", file.Size())
		return h.openArchive(lCtx, depth, rdr, dataOrErrChan)
	}
}
