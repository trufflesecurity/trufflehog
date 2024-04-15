package handlers

import (
	"fmt"
	"io"

	"github.com/gabriel-vasile/mimetype"
	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// FileHandler is an represents a handler for files.
// It has a single method, HandleFile, which takes a context and an io.Reader as input,
// and returns a channel of byte slices and an error.
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

type mimeType string

const (
	sevenZMime          mimeType = "application/x-7z-compressed"
	bzip2Mime           mimeType = "application/x-bzip2"
	gzipMime            mimeType = "application/x-gzip"
	rarCompressedMime   mimeType = "application/x-rar-compressed"
	rarMime             mimeType = "application/x-rar"
	tarMime             mimeType = "application/x-tar"
	zipMime             mimeType = "application/zip"
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
	machoMime           mimeType = "application/x-mach-binary"
	octetStreamMime     mimeType = "application/octet-stream"
)

var knownArchiveMimeTypes = map[mimeType]bool{
	sevenZMime:          true,
	bzip2Mime:           true,
	gzipMime:            true,
	rarCompressedMime:   true,
	rarMime:             true,
	tarMime:             true,
	zipMime:             true,
	gunzipMime:          true,
	gzippedMime:         true,
	gzipCompressedMime:  true,
	gzipDocumentMime:    true,
	xzMime:              true,
	msCabCompressedMime: true,
	rpmMime:             true,
	fitsMime:            true,
	xarMime:             true,
	warcMime:            true,
	cpioMime:            true,
	unixArMime:          true,
	arMime:              true,
	debMime:             true,
	lzipMime:            true,
	lzipXMime:           true,
	machoMime:           false,
	octetStreamMime:     false,
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
	defaultHandler := new(defaultHandler)

	var handler FileHandler
	switch mimeT {
	case arMime, unixArMime, debMime:
		handler = &arHandler{defaultHandler: defaultHandler}
	case rpmMime, cpioMime:
		handler = &rpmHandler{defaultHandler: defaultHandler}
	default:
		handler = defaultHandler
	}

	return handler, nil
}

// HandleFile orchestrates the complete file handling process for a given file.
// It determines the MIME type of the file, selects the appropriate handler based on this type, and processes the file.
// This function initializes the handling process and delegates to the specific handler to manage file
// extraction or processing. Errors at any stage (MIME type determination, handler retrieval,
// seeking, or file handling) result in a log entry and a false return value indicating failure.
// Successful handling passes the file content through a channel to be chunked and reported, returning true on success.
func HandleFile(
	ctx logContext.Context,
	reReader *diskbufferreader.DiskBufferReader,
	chunkSkel *sources.Chunk,
	reporter sources.ChunkReporter,
	options ...func(*fileHandlingConfig),
) bool {
	config := newFileHandlingConfig(options...)

	mimeT, err := mimetype.DetectReader(reReader)
	if err != nil {
		ctx.Logger().Error(err, "error detecting MIME type")
		return false
	}

	mime := mimeType(mimeT.String())
	if config.skipArchives && knownArchiveMimeTypes[mime] {
		ctx.Logger().V(5).Info("skipping archive file", "mime", mimeT.String())
		return true
	}

	handler, err := getHandlerForType(mime)
	if err != nil {
		ctx.Logger().Error(err, "error getting handler for type")
		return false
	}

	// Reset the reader to the start of the file since the MIME type detection may have read some bytes.
	if _, err := reReader.Seek(0, io.SeekStart); err != nil {
		ctx.Logger().Error(err, "error seeking to start of file")
		return false
	}

	archiveChan, err := handler.HandleFile(ctx, reReader) // Delegate to the specific handler to process the file.
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
func handleChunks(
	ctx logContext.Context,
	handlerChan chan []byte,
	chunkSkel *sources.Chunk,
	reporter sources.ChunkReporter,
) bool {
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
