package handlers

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/h2non/filetype"
	"github.com/mholt/archiver/v4"
	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// FileHandler is an represents a handler for files.
// It has a single method, HandleFile, which takes a context and an io.Reader as input,
// and returns a channel of byte slices and an error.
type FileHandler interface {
	HandleFile(ctx logContext.Context, input io.Reader) (chan []byte, error)
}

type mimeType string

const (
	arMimeType  mimeType = "application/x-unix-archive"
	rpmMimeType mimeType = "application/x-rpm"
	machOType   mimeType = "application/x-mach-binary"
	octetStream mimeType = "application/octet-stream"
)

// determineMimeType reads from the provided reader to detect the MIME type.
// It returns the detected MIME type and a new reader that includes the read portion.
func determineMimeType(reader io.Reader) (mimeType, io.Reader, error) {
	// A buffer of 512 bytes is used since many file formats store their magic numbers within the first 512 bytes.
	// If fewer bytes are read, MIME type detection may still succeed.
	buffer := make([]byte, 512)
	n, err := reader.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", nil, fmt.Errorf("unable to read file for MIME type detection: %w", err)
	}

	// Create a new reader that starts with the buffer we just read
	// and continues with the rest of the original reader.
	reader = io.MultiReader(bytes.NewReader(buffer[:n]), reader)

	kind, err := filetype.Match(buffer)
	if err != nil {
		return "", nil, fmt.Errorf("unable to determine file type: %w", err)
	}

	return mimeType(kind.MIME.Value), reader, nil
}

// GetHandlerForType dynamically selects and configures a FileHandler based on the provided MIME type. This method
// determines the appropriate handler to use: ARHandler for 'arMimeType', RPMHandler for 'rpmMimeType', and
// DefaultHandler for other types, which includes common archive formats like .zip, .tar, .gz, etc
// managed by the archiver library.
// The handler is then configured with provided Options, adapting it to specific operational needs.
// Returns the configured handler or an error if the handler type does not match the expected type.
func GetHandlerForType(mimeT mimeType, opts ...Option) (FileHandler, error) {
	var handler FileHandler
	switch mimeT {
	case arMimeType:
		handler = new(ARHandler)
	case rpmMimeType:
		handler = new(RPMHandler)
	case machOType, octetStream:
		fallthrough
	default:
		handler = new(DefaultHandler)
	}

	defaultHandler, ok := handler.(*DefaultHandler)
	if !ok {
		return handler, fmt.Errorf("handler is not a DefaultHandler: %T", handler)
	}

	defaultHandler.configure(opts...)
	return handler, nil
}

// HandleFile orchestrates the complete file handling process for a given file.
// It determines the MIME type of the file, selects the appropriate handler based on this type, and processes the file.
// This function initializes the handling process and delegates to the specific handler to manage file
// extraction or processing. Errors at any stage (MIME type determination, handler retrieval,
// seeking, or file handling) result in a log entry and a false return value indicating failure.
// Successful handling passes the file content through a channel to be chunked and reported, returning true on success.
func HandleFile(ctx logContext.Context, reReader *diskbufferreader.DiskBufferReader, chunkSkel *sources.Chunk, reporter sources.ChunkReporter, opts ...Option) bool {
	mimeT, _, err := determineMimeType(reReader)
	if err != nil {
		ctx.Logger().Error(err, "error determining MIME type")
		return false
	}

	handler, err := GetHandlerForType(mimeT, opts...)
	if err != nil {
		ctx.Logger().Error(err, "error getting handler for type")
		return false
	}

	// Reset the reader to the start of the file since the MIME type detection may have read some bytes.
	if _, err := reReader.Seek(0, io.SeekStart); err != nil {
		ctx.Logger().Error(err, "error seeking to start of file")
		return false
	}

	_, arReader, err := archiver.Identify("", reReader)
	if errors.Is(err, archiver.ErrNoMatch) {
		return false
	}

	archiveChan, err := handler.HandleFile(ctx, arReader) // Delegate to the specific handler to process the file.
	if err != nil {
		ctx.Logger().Error(err, "error handling file")
		return false
	}
	return handleChunks(ctx, archiveChan, chunkSkel, reporter)
}

// handleChunks reads data from the handlerChan and uses it to fill chunks according to a predefined skeleton (chunkSkel).
// Each filled chunk is reported using the provided reporter. This function manages the lifecycle of the channel,
// handling the termination condition when the channel closes and ensuring the cancellation of the operation if the context
// is done. It returns true if all chunks are processed successfully, otherwise returns false on errors or cancellation.
func handleChunks(ctx logContext.Context, handlerChan chan []byte, chunkSkel *sources.Chunk, reporter sources.ChunkReporter) bool {
	if handlerChan == nil {
		ctx.Logger().Error(fmt.Errorf("handler channel is nil"), "error handling chunks")
		return false
	}

	for {
		select {
		case data, open := <-handlerChan:
			if !open {
				ctx.Logger().V(5).Info("handler channel closed, all chunks processed")
				return true
			}
			chunk := *chunkSkel
			chunk.Data = data
			if err := reporter.ChunkOk(ctx, chunk); err != nil {
				ctx.Logger().Error(err, "error reporting chunk while handling chunks")
				return false
			}
		case <-ctx.Done():
			ctx.Logger().Error(ctx.Err(), "context done while handling chunks")
			return false
		}
	}
}
