package handlers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mholt/archiver/v4"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
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
	maxTimeout = time.Duration(30) * time.Second
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

// HandleFile processes the input as either an archive or non-archive based on its content,
// utilizing a single output channel. It first tries to identify the input as an archive. If it is an archive,
// it processes it accordingly; otherwise, it handles the input as non-archive content.
// The function returns a channel that will receive the extracted data bytes and an error if the initial setup fails.
func (h *archiveHandler) HandleFile(ctx logContext.Context, input fileReader) (chan []byte, error) {
	dataChan := make(chan []byte, defaultBufferSize)

	go func() {
		ctx, cancel := logContext.WithTimeout(ctx, maxTimeout)
		defer cancel()
		defer close(dataChan)

		// Update the metrics for the file processing.
		start := time.Now()
		var err error
		defer func() {
			h.measureLatencyAndHandleErrors(start, err)
			h.metrics.incFilesProcessed()
		}()

		if err = h.openArchive(ctx, 0, input, dataChan); err != nil {
			ctx.Logger().Error(err, "error unarchiving chunk.")
		}
	}()

	return dataChan, nil
}

var ErrMaxDepthReached = errors.New("max archive depth reached")

// openArchive recursively extracts content from an archive up to a maximum depth, handling nested archives if necessary.
// It takes a reader from which it attempts to identify and process the archive format. Depending on the archive type,
// it either decompresses or extracts the contents directly, sending data to the provided channel.
// Returns an error if the archive cannot be processed due to issues like exceeding maximum depth or unsupported formats.
func (h *archiveHandler) openArchive(ctx logContext.Context, depth int, reader fileReader, archiveChan chan []byte) error {
	if common.IsDone(ctx) {
		return ctx.Err()
	}

	if depth >= maxDepth {
		h.metrics.incMaxArchiveDepthCount()
		return ErrMaxDepthReached
	}

	arReader := reader.BufferedFileReader
	if reader.format == nil && depth > 0 {
		return h.handleNonArchiveContent(ctx, arReader, archiveChan)
	}

	switch archive := reader.format.(type) {
	case archiver.Decompressor:
		// Decompress tha archive and feed the decompressed data back into the archive handler to extract any nested archives.
		compReader, err := archive.OpenReader(arReader)
		if err != nil {
			return fmt.Errorf("error opening decompressor with format: %s %w", reader.format.Name(), err)
		}
		defer compReader.Close()

		rdr, err := newFileReader(compReader)
		if err != nil {
			if errors.Is(err, ErrEmptyReader) {
				ctx.Logger().V(5).Info("empty reader, skipping file")
				return nil
			}
			return fmt.Errorf("error creating custom reader: %w", err)
		}
		defer rdr.Close()

		return h.openArchive(ctx, depth+1, rdr, archiveChan)
	case archiver.Extractor:
		err := archive.Extract(logContext.WithValue(ctx, depthKey, depth+1), arReader, nil, h.extractorHandler(archiveChan))
		if err != nil {
			return fmt.Errorf("error extracting archive with format: %s: %w", reader.format.Name(), err)
		}
		return nil
	default:
		return fmt.Errorf("unknown archive type: %s", reader.mimeType)
	}
}

// extractorHandler creates a closure that handles individual files extracted by an archiver.
// It logs the extraction, checks for cancellation, and decides whether to skip the file based on its name or type,
// particularly for binary files if configured to skip. If the file is not skipped, it recursively calls openArchive
// to handle nested archives or to continue processing based on the file's content and depth in the archive structure.
func (h *archiveHandler) extractorHandler(archiveChan chan []byte) func(context.Context, archiver.File) error {
	return func(ctx context.Context, file archiver.File) error {
		lCtx := logContext.WithValues(
			logContext.AddLogger(ctx),
			"filename", file.Name(),
			"size", file.Size(),
		)
		lCtx.Logger().V(5).Info("Handling extracted file.")

		if file.IsDir() || file.LinkTarget != "" {
			lCtx.Logger().V(5).Info("skipping directory or symlink")
			return nil
		}

		if common.IsDone(ctx) {
			return ctx.Err()
		}

		depth := 0
		if ctxDepth, ok := ctx.Value(depthKey).(int); ok {
			depth = ctxDepth
		}

		fileSize := file.Size()
		if int(fileSize) > maxSize {
			lCtx.Logger().V(3).Info("skipping file due to size", "size", fileSize)
			h.metrics.incFilesSkipped()
			return nil
		}

		if common.SkipFile(file.Name()) || common.IsBinary(file.Name()) {
			lCtx.Logger().V(5).Info("skipping file")
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

		rdr, err := newFileReader(f)
		if err != nil {
			if errors.Is(err, ErrEmptyReader) {
				lCtx.Logger().V(5).Info("empty reader, skipping file")
				return nil
			}
			return fmt.Errorf("error creating custom reader: %w", err)
		}
		defer rdr.Close()

		h.metrics.incFilesProcessed()
		h.metrics.observeFileSize(fileSize)

		return h.openArchive(lCtx, depth, rdr, archiveChan)
	}
}
