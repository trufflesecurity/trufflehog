package handlers

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"github.com/mholt/archiver/v4"
	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type ctxKey int

const depthKey ctxKey = iota

var (
	maxDepth   = 5
	maxSize    = 250 * 1024 * 1024 // 20MB
	maxTimeout = time.Duration(30) * time.Second

	defaultBufferSize = 512
)

// SetArchiveMaxSize sets the maximum size of the archive.
func SetArchiveMaxSize(size int) {
	maxSize = size
}

// SetArchiveMaxDepth sets the maximum depth of the archive.
func SetArchiveMaxDepth(depth int) {
	maxDepth = depth
}

// SetArchiveMaxTimeout sets the maximum timeout for the archive handler.
func SetArchiveMaxTimeout(timeout time.Duration) {
	maxTimeout = timeout
}

// Option is a function type that applies a configuration to a DefaultHandler.
// It is used to modify the behavior of a DefaultHandler.
type Option func(handler *DefaultHandler)

// WithSkipBinaries returns an Option that configures whether to skip binary files.
// This function is used to create an Option that sets the skipBinaries field of a DefaultHandler.
// If skip is true, the DefaultHandler will skip binary files.
func WithSkipBinaries(skip bool) Option {
	return func(h *DefaultHandler) { h.skipBinaries = skip }
}

// WithSkipArchives returns an Option that configures whether to skip archive files.
// This function is used to create an Option that sets the skipArchives field of a DefaultHandler.
// If skip is true, the DefaultHandler will skip archive files.
func WithSkipArchives(skip bool) Option {
	return func(h *DefaultHandler) { h.skipArchives = skip }

}

// DefaultHandler provides a base implementation for file handlers, encapsulating common behaviors
// needed across different handlers, such as skipping binary files. This handler is embedded in other
// specialized handlers to ensure consistent application of these common behaviors and to simplify
// the extension of handler functionalities.
type DefaultHandler struct {
	skipBinaries bool // Controls whether binary files should be processed.
	skipArchives bool // Controls whether archive files should be processed.
}

// configure applies a series of Options to the handler, allowing for flexible configuration of
// handler-specific settings such as whether to skip binary files. This method supports dynamic
// customization of handler behavior at runtime.
func (h *DefaultHandler) configure(opts ...Option) {
	for _, opt := range opts {
		opt(h)
	}
}

// HandleFile initiates the asynchronous extraction of archive contents. It creates a channel to send extracted data
// and starts a goroutine that handles the archive opening process. It utilizes a context with a timeout to ensure
// that the extraction process does not exceed a predefined maximum duration.
// The function returns a channel that will receive the extracted data bytes and an error if the initial setup fails.
func (h *DefaultHandler) HandleFile(ctx logContext.Context, input *diskbufferreader.DiskBufferReader) (chan []byte, error) {
	if h.skipArchives {
		return nil, nil
	}

	archiveChan := make(chan []byte, defaultBufferSize)
	go func() {
		ctx, cancel := logContext.WithTimeout(ctx, maxTimeout)
		defer cancel()
		defer close(archiveChan)

		if err := h.openArchive(ctx, 0, input, archiveChan); err != nil {
			ctx.Logger().Error(err, "error unarchiving chunk.")
		}
	}()
	return archiveChan, nil
}

var ErrMaxDepthReached = errors.New("max archive depth reached")

// openArchive recursively extracts content from an archive up to a maximum depth, handling nested archives if necessary.
// It takes a reader from which it attempts to identify and process the archive format. Depending on the archive type,
// it either decompresses or extracts the contents directly, sending data to the provided channel.
// Returns an error if the archive cannot be processed due to issues like exceeding maximum depth or unsupported formats.
func (h *DefaultHandler) openArchive(ctx logContext.Context, depth int, reader io.Reader, archiveChan chan []byte) error {
	if common.IsDone(ctx) {
		return ctx.Err()
	}

	if depth >= maxDepth {
		return ErrMaxDepthReached
	}

	format, arReader, err := archiver.Identify("", reader)
	if errors.Is(err, archiver.ErrNoMatch) && depth > 0 {
		return h.handleNonArchiveContent(ctx, arReader, archiveChan)
	}

	if err != nil {
		return fmt.Errorf("error identifying archive: %w", err)
	}

	switch archive := format.(type) {
	case archiver.Decompressor:
		// Decompress tha archive and feed the decompressed data back into the archive handler to extract any nested archives.
		compReader, err := archive.OpenReader(arReader)
		if err != nil {
			return err
		}

		defer compReader.Close()

		return h.openArchive(ctx, depth+1, compReader, archiveChan)
	case archiver.Extractor:
		return archive.Extract(logContext.WithValue(ctx, depthKey, depth+1), arReader, nil, h.extractorHandler(archiveChan))
	default:
		return fmt.Errorf("unknown archive type: %s", format.Name())
	}
}

// extractorHandler creates a closure that handles individual files extracted by an archiver.
// It logs the extraction, checks for cancellation, and decides whether to skip the file based on its name or type,
// particularly for binary files if configured to skip. If the file is not skipped, it recursively calls openArchive
// to handle nested archives or to continue processing based on the file's content and depth in the archive structure.
func (h *DefaultHandler) extractorHandler(archiveChan chan []byte) func(context.Context, archiver.File) error {
	return func(ctx context.Context, file archiver.File) error {
		lCtx := logContext.WithValues(
			logContext.AddLogger(ctx),
			"filename", file.Name(),
			"size", file.Size(),
		)
		lCtx.Logger().V(5).Info("Handling extracted file.")

		if common.IsDone(ctx) {
			return ctx.Err()
		}

		depth := 0
		if ctxDepth, ok := ctx.Value(depthKey).(int); ok {
			depth = ctxDepth
		}
		if int(file.Size()) > maxSize {
			lCtx.Logger().V(3).Info("skipping file due to size")
			return nil
		}

		if common.SkipFile(file.Name()) {
			lCtx.Logger().V(5).Info("skipping file")
			return nil
		}

		if h.skipBinaries && common.IsBinary(file.Name()) {
			lCtx.Logger().V(5).Info("skipping binary file")
			return nil
		}

		fReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fReader.Close()

		return h.openArchive(lCtx, depth, fReader, archiveChan)
	}
}

// handleNonArchiveContent processes files that do not contain nested archives, serving as the final stage in the
// extraction/decompression process. It reads the content to detect its MIME type and decides whether to skip based
// on the type, particularly for binary files. It manages reading file chunks and writing them to the archive channel,
// effectively collecting the final bytes for further processing. This function is a key component in ensuring that all
// file content, regardless of being an archive or not, is handled appropriately.
func (h *DefaultHandler) handleNonArchiveContent(ctx logContext.Context, reader io.Reader, archiveChan chan []byte) error {
	bufReader := bufio.NewReaderSize(reader, defaultBufferSize)
	// A buffer of 512 bytes is used since many file formats store their magic numbers within the first 512 bytes.
	// If fewer bytes are read, MIME type detection may still succeed.
	buffer, err := bufReader.Peek(defaultBufferSize)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("unable to read file for MIME type detection: %w", err)
	}

	mime := mimetype.Detect(buffer)
	mimeT := mimeType(mime.String())

	if common.SkipFile(mime.Extension()) {
		ctx.Logger().V(5).Info("skipping file", "ext", mimeT)
		return nil
	}

	if h.skipBinaries {
		if common.IsBinary(mime.Extension()) || mimeT == machOType || mimeT == octetStream {
			ctx.Logger().V(5).Info("skipping binary file", "ext", mimeT)
			return nil
		}
	}

	chunkReader := sources.NewChunkReader()
	chunkResChan := chunkReader(ctx, bufReader)
	for data := range chunkResChan {
		if err := data.Error(); err != nil {
			ctx.Logger().Error(err, "error reading chunk")
			continue
		}
		if err := common.CancellableWrite(ctx, archiveChan, data.Bytes()); err != nil {
			return err
		}
	}
	return nil
}
