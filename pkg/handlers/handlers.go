package handlers

import (
	"errors"
	"fmt"
	"io"

	"github.com/gabriel-vasile/mimetype"
	"github.com/mholt/archiver/v4"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/readers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// readSeekCloser is an interface that combines the functionality of io.ReadSeekCloser and io.ReaderAt.
// It supports reading data, seeking within an open resource, and closing the resource once operations are complete.
// Additionally, it allows reading from a specific offset within the resource without altering its current position,
// enabling efficient and flexible data access patterns. This interface is particularly useful for handling files
// or other data streams where random access and sequential processing are required.
type readSeekCloser interface {
	io.ReadSeekCloser
	io.ReaderAt
}

type customReader struct {
	format   archiver.Format
	mimeType mimeType
	*readers.BufferedFileReader
	isArchive bool
}

func newCustomReader(ctx logContext.Context, r io.Reader) (customReader, error) {
	var custom customReader
	rdr, err := readers.NewBufferedFileReader(ctx, r)
	if err != nil {
		return custom, fmt.Errorf("error creating random access reader: %w", err)
	}
	custom.BufferedFileReader = rdr

	format, reader, err := archiver.Identify("", rdr)
	switch {
	case err == nil: // Archive detected
		custom.isArchive = true
		custom.mimeType = mimeType(format.Name())
		custom.format = format
	case errors.Is(err, archiver.ErrNoMatch):
		// Not an archive, process as a regular file.
		mimeT, err := mimetype.DetectReader(reader)
		if err != nil {
			return custom, fmt.Errorf("error detecting MIME type: %w", err)
		}
		custom.mimeType = mimeType(mimeT.String())
	default: // Error identifying archive
		return custom, fmt.Errorf("error identifying archive: %w", err)
	}

	if _, err = rdr.Seek(0, io.SeekStart); err != nil {
		return custom, fmt.Errorf("error seeking to start of file: %w", err)
	}

	// if format != nil {
	// 	custom.format = format.Name()
	// }

	// if _, err = rdr.Seek(0, io.SeekStart); err != nil {
	// 	return custom, fmt.Errorf("error seeking to start of file: %w", err)
	// }

	return custom, nil
}

// FileHandler represents a handler for files.
// It has a single method, HandleFile, which takes a context and a readSeekCloser as input,
// and returns a channel of byte slices and an error.
// The readSeekCloser extends io.ReadSeekCloser with io.ReaderAt capabilities,
// allowing handlers to perform random and direct access on the file content efficiently.
type FileHandler interface {
	HandleFile(ctx logContext.Context, reader customReader) (chan []byte, error)
}

// fileHandlingConfig encapsulates configuration settings that control the behavior of file processing.
type fileHandlingConfig struct{ skipArchives bool }

// newFileHandlingConfig creates a default fileHandlingConfig with default settings.
// Optional functional parameters can customize the configuration.
func newFileHandlingConfig(options ...func(*fileHandlingConfig)) fileHandlingConfig {
	config := fileHandlingConfig{}
	for _, option := range options {
		option(&config)
	}

	return config
}

// WithSkipArchives sets the skipArchives field of the fileHandlingConfig.
// If skip is true, the FileHandler will skip archive files.
func WithSkipArchives(skip bool) func(*fileHandlingConfig) {
	return func(c *fileHandlingConfig) { c.skipArchives = skip }
}

type handlerType string

const (
	defaultHandlerType handlerType = "default"
	arHandlerType      handlerType = "ar"
	rpmHandlerType     handlerType = "rpm"
)

type mimeType string

const (
	rpmMime    mimeType = "application/x-rpm"
	cpioMime   mimeType = "application/cpio"
	unixArMime mimeType = "application/x-unix-archive"
	arMime     mimeType = "application/x-archive"
	debMime    mimeType = "application/vnd.debian.binary-package"
)

// getHandlerForType dynamically selects and configures a FileHandler based on the provided MIME type.
// This method uses specialized handlers for specific archive types and RPM packages:
// - arHandler is used for 'arMime', 'unixArMime', and 'debMime' which include Unix archives and Debian packages.
// - rpmHandler is used for 'rpmMime' and 'cpioMime', handling RPM and CPIO archives.
// For all other MIME types, which typically include common archive formats like .zip, .tar, .gz, etc.,
// a defaultHandler is used, leveraging the archiver library to manage these formats.
// The chosen handler is then configured with provided options, adapting it to specific operational needs.
// Returns the configured handler.
func getHandlerForType(mimeT mimeType) FileHandler {
	var handler FileHandler
	switch mimeT {
	case arMime, unixArMime, debMime:
		handler = newARHandler()
	case rpmMime, cpioMime:
		handler = newRPMHandler()
	default:
		handler = newDefaultHandler(defaultHandlerType)
	}

	return handler
}

// HandleFile orchestrates the complete file handling process for a given file.
// It determines the MIME type of the file, selects the appropriate handler based on this type, and processes the file.
// This function initializes the handling process and delegates to the specific handler to manage file
// extraction or processing. Errors at any stage (MIME type determination, handler retrieval,
// seeking, or file handling) result in an error return value.
// Successful handling passes the file content through a channel to be chunked and reported.
//
// The function takes an io.Reader as input and creates a readSeekCloser using bufferwriter.NewBufferReadSeekCloser.
// The readSeekCloser supports seeking and provides an io.ReaderAt interface, which is essential for
// file handlers requiring random access to file content.
//
// If the skipArchives option is set to true and the detected MIME type is a known archive type,
// the function will skip processing the file and return nil.
func HandleFile(
	ctx logContext.Context,
	reader io.Reader,
	chunkSkel *sources.Chunk,
	reporter sources.ChunkReporter,
	options ...func(*fileHandlingConfig),
) error {
	// rdr, err := readers.NewBufferedFileReader(ctx, reader)
	// if err != nil {
	// 	return fmt.Errorf("error creating random access reader: %w", err)
	// }
	// defer rdr.Close()
	//
	// mimeT, err := mimetype.DetectReader(rdr)
	// if err != nil {
	// 	return fmt.Errorf("error detecting MIME type: %w", err)
	// }
	// mime := mimeType(mimeT.String())
	//
	// if _, err = rdr.Seek(0, io.SeekStart); err != nil {
	// 	return fmt.Errorf("error seeking to start of file: %w", err)
	// }
	//
	// config := newFileHandlingConfig(options...)
	//
	// isArchive := false
	// _, _, err = archiver.Identify("", rdr)
	// switch {
	// case err == nil: // Archive detected
	// 	isArchive = true
	// case errors.Is(err, archiver.ErrNoMatch):
	// 	// Not an archive, process as a regular file.
	// default: // Error identifying archive
	// 	return fmt.Errorf("error identifying archive: %w", err)
	// }
	//
	// if _, err = rdr.Seek(0, io.SeekStart); err != nil {
	// 	return fmt.Errorf("error seeking to start of file: %w", err)
	// }
	//

	rdr, err := newCustomReader(ctx, reader)
	if err != nil {
		return fmt.Errorf("error creating custom reader: %w", err)
	}
	defer rdr.Close()

	config := newFileHandlingConfig(options...)
	if config.skipArchives && rdr.isArchive {
		ctx.Logger().V(5).Info("skipping archive file", "mime", rdr.mimeType)
		return nil
	}

	handler := getHandlerForType(rdr.mimeType)
	archiveChan, err := handler.HandleFile(ctx, rdr) // Delegate to the specific handler to process the file.
	if err != nil {
		return fmt.Errorf("error handling file: %w", err)
	}

	return handleChunks(ctx, archiveChan, chunkSkel, reporter)
}

// handleChunks reads data from the handlerChan and uses it to fill chunks according to a predefined skeleton (chunkSkel).
// Each filled chunk is reported using the provided reporter. This function manages the lifecycle of the channel,
// handling the termination condition when the channel closes and ensuring the cancellation of the operation if the context
// is done. It returns true if all chunks are processed successfully, otherwise returns false on errors or cancellation.
func handleChunks(
	ctx logContext.Context,
	handlerChan chan []byte,
	chunkSkel *sources.Chunk,
	reporter sources.ChunkReporter,
) error {
	if handlerChan == nil {
		return fmt.Errorf("handler channel is nil")
	}

	for {
		select {
		case data, open := <-handlerChan:
			if !open {
				ctx.Logger().V(5).Info("handler channel closed, all chunks processed")
				return nil
			}
			chunk := *chunkSkel
			chunk.Data = data
			if err := reporter.ChunkOk(ctx, chunk); err != nil {
				return fmt.Errorf("error reporting chunk: %w", err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
