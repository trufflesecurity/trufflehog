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

// fileReader is a custom reader that wraps an io.Reader and provides additional functionality for identifying
// and handling different file types. It abstracts away the complexity of detecting file formats, MIME types,
// and archive types, allowing for a more modular and extensible file handling process.
//
// fileReader leverages the archiver and mimetype packages for file type identification and provides information
// about the detected file format, MIME type, and whether the file is an archive. This information can be
// used by FileHandler implementations to make decisions on how to process the file.
//
// The IsGenericArchive field indicates whether the file represents an archive format that is supported by the
// archiver library. This allows FileHandler implementations to determine if the file can be processed using
// the default archive handling capabilities provided by the archiver package.
//
// By encapsulating the file type detection logic, fileReader simplifies the implementation of FileHandler and
// promotes a more cohesive and maintainable codebase. It also embeds a BufferedFileReader to provide efficient
// random access to the file content.
type fileReader struct {
	format   archiver.Format
	mimeType mimeType
	*readers.BufferedFileReader
	isGenericArchive bool
}

var ErrEmptyReader = errors.New("reader is empty")

func newFileReader(r io.ReadCloser) (fileReader, error) {
	defer r.Close()

	var (
		reader fileReader
		rdr    *readers.BufferedFileReader
		err    error
	)
	rdr, err = readers.NewBufferedFileReader(r)
	if err != nil {
		return reader, fmt.Errorf("error creating random access reader: %w", err)
	}
	reader.BufferedFileReader = rdr

	// Ensure the reader is closed if an error occurs after the reader is created.
	// During non-error conditions, the caller is responsible for closing the reader.
	defer func() {
		if err != nil && rdr != nil {
			_ = rdr.Close()
		}
	}()

	// Check if the reader is empty.
	if rdr.Size() == 0 {
		return reader, ErrEmptyReader
	}

	format, arReader, err := archiver.Identify("", rdr)
	switch {
	case err == nil: // Archive detected
		reader.isGenericArchive = true
		reader.mimeType = mimeType(format.Name())
		reader.format = format
	case errors.Is(err, archiver.ErrNoMatch):
		// Not an archive handled by archiver, try to detect MIME type.
		// This will occur for un-supported archive types and non-archive files. (ex: .deb, .rpm, .txt)
		mimeT, err := mimetype.DetectReader(arReader)
		if err != nil {
			return reader, fmt.Errorf("error detecting MIME type: %w", err)
		}
		reader.mimeType = mimeType(mimeT.String())
	default: // Error identifying archive
		return reader, fmt.Errorf("error identifying archive: %w", err)
	}

	if _, err = rdr.Seek(0, io.SeekStart); err != nil {
		return reader, fmt.Errorf("error seeking to start of file: %w", err)
	}

	return reader, nil
}

// FileHandler represents a handler for files.
// It has a single method, HandleFile, which takes a context and a fileReader as input,
// and returns a channel of byte slices and an error.
type FileHandler interface {
	HandleFile(ctx logContext.Context, reader fileReader) (chan []byte, error)
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
	archiveHandlerType handlerType = "archive"
	arHandlerType      handlerType = "ar"
	rpmHandlerType     handlerType = "rpm"
	defaultHandlerType handlerType = "default"
)

type mimeType string

const (
	rpmMime    mimeType = "application/x-rpm"
	cpioMime   mimeType = "application/cpio"
	unixArMime mimeType = "application/x-unix-archive"
	arMime     mimeType = "application/x-archive"
	debMime    mimeType = "application/vnd.debian.binary-package"
)

// selectHandler dynamically selects and configures a FileHandler based on the provided fileReader.
// The fileReader contains information about the MIME type and whether the file is an archive.
// This method uses specialized handlers for specific file types:
// - arHandler is used for Unix archives and Debian packages ('arMime', 'unixArMime', and 'debMime').
// - rpmHandler is used for RPM and CPIO archives ('rpmMime' and 'cpioMime').
// - archiveHandler is used for common archive formats supported by the archiver library (.zip, .tar, .gz, etc.).
// - defaultHandler is used for non-archive files.
// The selected handler is then returned, ready to handle the file according to its specific format and requirements.
func selectHandler(file fileReader) FileHandler {
	switch file.mimeType {
	case arMime, unixArMime, debMime:
		return newARHandler()
	case rpmMime, cpioMime:
		return newRPMHandler()
	default:
		if file.isGenericArchive {
			return newArchiveHandler()
		}
		return newDefaultHandler(defaultHandlerType)
	}
}

// HandleFile orchestrates the complete file handling process for a given file.
// It determines the MIME type of the file, selects the appropriate handler based on this type, and processes the file.
// This function initializes the handling process and delegates to the specific handler to manage file
// extraction or processing. Errors at any stage result in an error return value.
// Successful handling passes the file content through a channel to be chunked and reported.
// The function will close the reader when it has consumed all the data.
//
// If the skipArchives option is set to true and the detected MIME type is a known archive type,
// the function will skip processing the file and return nil.
func HandleFile(
	ctx logContext.Context,
	reader io.ReadCloser,
	chunkSkel *sources.Chunk,
	reporter sources.ChunkReporter,
	options ...func(*fileHandlingConfig),
) error {
	if reader == nil {
		return fmt.Errorf("reader is nil")
	}

	rdr, err := newFileReader(reader)
	if err != nil {
		if errors.Is(err, ErrEmptyReader) {
			ctx.Logger().V(5).Info("empty reader, skipping file")
			return nil
		}
		return fmt.Errorf("error creating custom reader: %w", err)
	}
	defer rdr.Close()

	config := newFileHandlingConfig(options...)
	if config.skipArchives && rdr.isGenericArchive {
		ctx.Logger().V(5).Info("skipping archive file", "mime", rdr.mimeType)
		return nil
	}

	handler := selectHandler(rdr)
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
