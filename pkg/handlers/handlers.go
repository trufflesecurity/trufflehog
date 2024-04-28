package handlers

import (
	"fmt"
	"io"

	"github.com/gabriel-vasile/mimetype"
	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// FileHandler represents a handler for files.
// It has a single method, HandleFile, which takes a context and a *diskbufferreader.DiskBufferReader as input,
// and returns a channel of byte slices and an error.
// The DiskBufferReader provides an io.ReaderAt interface and supports seeking, allowing handlers to perform
// random access on the file content if needed.
type FileHandler interface {
	HandleFile(ctx logContext.Context, reader *diskbufferreader.DiskBufferReader) (chan []byte, error)
}

// fileHandlingConfig encapsulates configuration settings that control the behavior of file processing.
type fileHandlingConfig struct{ skipArchives bool }

// newFileHandlingConfig creates a default fileHandlingConfig with default settings.
// Optional functional parameters can customize the configuration.
func newFileHandlingConfig(options ...func(*fileHandlingConfig)) *fileHandlingConfig {
	config := new(fileHandlingConfig)
	for _, option := range options {
		option(config)
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
	sevenZMime          mimeType = "application/x-7z-compressed"
	bzip2Mime           mimeType = "application/x-bzip2"
	rarCompressedMime   mimeType = "application/x-rar-compressed"
	rarMime             mimeType = "application/x-rar"
	tarMime             mimeType = "application/x-tar"
	zipMime             mimeType = "application/zip"
	gxzipMime           mimeType = "application/x-gzip"
	gzipMime            mimeType = "application/gzip"
	gunzipMime          mimeType = "application/x-gunzip"
	gzippedMime         mimeType = "application/gzipped"
	gzipCompressedMime  mimeType = "application/x-gzip-compressed"
	gzipDocumentMime    mimeType = "gzip/document"
	xzMime              mimeType = "application/x-xz"
	msCabCompressedMime mimeType = "application/vnd.ms-cab-compressed"
	rpmMime             mimeType = "application/x-rpm"
	fitsMime            mimeType = "application/fits"
	xarMime             mimeType = "application/x-xar"
	warcMime            mimeType = "application/warc"
	cpioMime            mimeType = "application/cpio"
	unixArMime          mimeType = "application/x-unix-archive"
	arMime              mimeType = "application/x-archive"
	debMime             mimeType = "application/vnd.debian.binary-package"
	lzipMime            mimeType = "application/lzip"
	lzipXMime           mimeType = "application/x-lzip"
)

var knownArchiveMimeTypes = map[mimeType]struct{}{
	sevenZMime:          {},
	bzip2Mime:           {},
	gzipMime:            {},
	gxzipMime:           {},
	rarCompressedMime:   {},
	rarMime:             {},
	tarMime:             {},
	zipMime:             {},
	gunzipMime:          {},
	gzippedMime:         {},
	gzipCompressedMime:  {},
	gzipDocumentMime:    {},
	xzMime:              {},
	msCabCompressedMime: {},
	rpmMime:             {},
	fitsMime:            {},
	xarMime:             {},
	warcMime:            {},
	cpioMime:            {},
	unixArMime:          {},
	arMime:              {},
	debMime:             {},
	lzipMime:            {},
	lzipXMime:           {},
}

// getHandlerForType dynamically selects and configures a FileHandler based on the provided MIME type.
// This method uses specialized handlers for specific archive types and RPM packages:
// - arHandler is used for 'arMime', 'unixArMime', and 'debMime' which include Unix archives and Debian packages.
// - rpmHandler is used for 'rpmMime' and 'cpioMime', handling RPM and CPIO archives.
// For all other MIME types, which typically include common archive formats like .zip, .tar, .gz, etc.,
// a defaultHandler is used, leveraging the archiver library to manage these formats.
// The chosen handler is then configured with provided options, adapting it to specific operational needs.
// Returns the configured handler or an error if the handler type does not match the expected type.
func getHandlerForType(mimeT mimeType) (FileHandler, error) {
	var handler FileHandler
	switch mimeT {
	case arMime, unixArMime, debMime:
		handler = newARHandler()
	case rpmMime, cpioMime:
		handler = newRPMHandler()
	default:
		handler = newDefaultHandler(defaultHandlerType)
	}

	return handler, nil
}

// HandleFile orchestrates the complete file handling process for a given file.
// It determines the MIME type of the file, selects the appropriate handler based on this type, and processes the file.
// This function initializes the handling process and delegates to the specific handler to manage file
// extraction or processing. Errors at any stage (MIME type determination, handler retrieval,
// seeking, or file handling) result in an error return value.
// Successful handling passes the file content through a channel to be chunked and reported.
//
// The function takes an io.Reader as input and wraps it with a diskbufferreader.DiskBufferReader to support
// seeking and to provide an io.ReaderAt interface. This is necessary for certain file handlers that require
// random access to the file content.
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
	config := newFileHandlingConfig(options...)

	reReader, err := diskbufferreader.New(reader, diskbufferreader.WithBufferName(cleantemp.MkFilename()))
	if err != nil {
		return err
	}
	defer reReader.Close()

	mimeT, err := mimetype.DetectReader(reReader)
	if err != nil {
		return fmt.Errorf("error detecting MIME type: %w", err)
	}

	mime := mimeType(mimeT.String())
	if _, ok := knownArchiveMimeTypes[mime]; ok && config.skipArchives {
		ctx.Logger().V(5).Info("skipping archive file", "mime", mimeT.String())
		return nil
	}

	// Reset the reader to the start of the file since the MIME type detection may have read some bytes.
	if _, err := reReader.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("error seeking to start of file: %w", err)
	}

	handler, err := getHandlerForType(mime)
	if err != nil {
		return fmt.Errorf("error getting handler for type: %w", err)
	}

	archiveChan, err := handler.HandleFile(ctx, reReader) // Delegate to the specific handler to process the file.
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
