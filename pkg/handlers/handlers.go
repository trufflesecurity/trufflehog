package handlers

import (
	"bufio"
	"errors"
	"fmt"
	"io"

	"github.com/gabriel-vasile/mimetype"
	"github.com/mholt/archiver/v4"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/iobuf"
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
	format           archiver.Format
	mime             *mimetype.MIME
	isGenericArchive bool

	*iobuf.BufferedReadSeeker
}

var ErrEmptyReader = errors.New("reader is empty")

// mimeTypeReader wraps an io.Reader with MIME type information.
// This type is used to pass content through the processing pipeline
// while carrying its detected MIME type, avoiding redundant type detection.
type mimeTypeReader struct {
	mimeExt  string
	mimeName mimeType
	io.Reader
}

// newMimeTypeReaderFromFileReader creates a new mimeTypeReader from a fileReader.
func newMimeTypeReaderFromFileReader(r fileReader) mimeTypeReader {
	return mimeTypeReader{
		mimeExt:  r.mime.Extension(),
		mimeName: mimeType(r.mime.String()),
		Reader:   r.BufferedReadSeeker,
	}
}

// newMimeTypeReader creates a new mimeTypeReader from an io.Reader.
// It uses a bufio.Reader to perform MIME type detection on the input reader
// without consuming it, by peeking into the first 3072 bytes of the input.
// This encapsulates both the original reader and the detected MIME type information.
// This function is particularly useful for specialized archive handlers
// that need to pass extracted content to the default handler without modifying the original reader.
func newMimeTypeReader(r io.Reader) (mimeTypeReader, error) {
	const defaultMinBufferSize = 3072
	bufReader := bufio.NewReaderSize(r, defaultMinBufferSize)
	// A buffer of 512 bytes is used since many file formats store their magic numbers within the first 512 bytes.
	// If fewer bytes are read, MIME type detection may still succeed.
	buffer, err := bufReader.Peek(defaultMinBufferSize)
	if err != nil && !errors.Is(err, io.EOF) {
		return mimeTypeReader{}, fmt.Errorf("unable to read file for MIME type detection: %w", err)
	}

	mime := mimetype.Detect(buffer)

	return mimeTypeReader{mimeExt: mime.Extension(), mimeName: mimeType(mime.String()), Reader: bufReader}, nil
}

// newFileReader creates a fileReader from an io.Reader, optionally using BufferedFileWriter for certain formats.
func newFileReader(r io.Reader) (fileReader, error) {
	var fReader fileReader

	fReader.BufferedReadSeeker = iobuf.NewBufferedReaderSeeker(r)

	mime, err := mimetype.DetectReader(fReader)
	if err != nil {
		return fReader, fmt.Errorf("unable to detect MIME type: %w", err)
	}
	fReader.mime = mime

	// Reset the reader to the beginning because DetectReader consumes the reader.
	if _, err := fReader.Seek(0, io.SeekStart); err != nil {
		return fReader, fmt.Errorf("error resetting reader after MIME detection: %w", err)
	}

	// If a MIME type is known to not be an archive type, we might as well return here rather than
	// paying the I/O penalty of an archiver.Identify() call that won't identify anything.
	if _, ok := skipArchiverMimeTypes[mimeType(mime.String())]; ok {
		return fReader, nil
	}

	format, _, err := archiver.Identify("", fReader)
	switch {
	case err == nil:
		fReader.isGenericArchive = true
		fReader.format = format

	case errors.Is(err, archiver.ErrNoMatch):
		// Not an archive handled by archiver.
		// Continue with the default reader.
	default:
		return fReader, fmt.Errorf("error identifying archive: %w", err)
	}

	// Reset the reader to the beginning again to allow the handler to read from the start.
	// This is necessary because Identify consumes the reader.
	if _, err := fReader.Seek(0, io.SeekStart); err != nil {
		return fReader, fmt.Errorf("error resetting reader after archive identification: %w", err)
	}

	return fReader, nil
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
	rpmMime      mimeType = "application/x-rpm"
	cpioMime     mimeType = "application/cpio"
	unixArMime   mimeType = "application/x-unix-archive"
	arMime       mimeType = "application/x-archive"
	debMime      mimeType = "application/vnd.debian.binary-package"
	textMime     mimeType = "text/plain; charset=utf-8"
	xmlMime      mimeType = "text/xml"
	jsonMime     mimeType = "application/json"
	csvMime      mimeType = "text/csv"
	tsvMime      mimeType = "text/tab-separated-values"
	geoJSONMine  mimeType = "application/vnd.geo+json"
	ndjsonMime   mimeType = "application/x-ndjson"
	htmlMime     mimeType = "text/html"
	phpTextMime  mimeType = "text/x-php"
	rtfTextMime  mimeType = "text/rtf"
	jsAppMime    mimeType = "application/javascript"
	jsTextMime   mimeType = "text/javascript"
	jsMime       mimeType = "application/x-javascript"
	srtMime      mimeType = "application/x-subrip"
	srtXMime     mimeType = "application/x-srt"
	srtTextMime  mimeType = "text/x-srt"
	vttMime      mimeType = "text/vtt"
	luaMime      mimeType = "text/x-lua"
	perlMime     mimeType = "text/x-perl"
	pythonMime   mimeType = "text/x-python"
	pyAppMime    mimeType = "application/x-python"
	pyScriptMime mimeType = "application/x-script.python"
	tclTextMime  mimeType = "text/x-tcl"
	tclMime      mimeType = "application/x-tcl"
)

// skipArchiverMimeTypes is a set of MIME types that should bypass archiver library processing because they are either
// text-based or archives not supported by the library.
var skipArchiverMimeTypes = map[mimeType]struct{}{
	arMime:       {},
	unixArMime:   {},
	debMime:      {},
	rpmMime:      {},
	cpioMime:     {},
	textMime:     {},
	xmlMime:      {},
	jsonMime:     {},
	csvMime:      {},
	tsvMime:      {},
	geoJSONMine:  {},
	ndjsonMime:   {},
	htmlMime:     {},
	phpTextMime:  {},
	rtfTextMime:  {},
	jsAppMime:    {},
	jsTextMime:   {},
	jsMime:       {},
	srtMime:      {},
	srtXMime:     {},
	srtTextMime:  {},
	vttMime:      {},
	luaMime:      {},
	perlMime:     {},
	pythonMime:   {},
	pyAppMime:    {},
	pyScriptMime: {},
	tclTextMime:  {},
	tclMime:      {},
}

// selectHandler dynamically selects and configures a FileHandler based on the provided |mimetype| type and archive flag.
// The fileReader contains information about the MIME type and whether the file is an archive.
// This method uses specialized handlers for specific file types:
// - arHandler is used for Unix archives and Debian packages ('arMime', 'unixArMime', and 'debMime').
// - rpmHandler is used for RPM and CPIO archives ('rpmMime' and 'cpioMime').
// - archiveHandler is used for common archive formats supported by the archiver library (.zip, .tar, .gz, etc.).
// - defaultHandler is used for non-archive files.
// The selected handler is then returned, ready to handle the file according to its specific format and requirements.
func selectHandler(mimeT mimeType, isGenericArchive bool) FileHandler {
	switch mimeT {
	case arMime, unixArMime, debMime:
		return newARHandler()
	case rpmMime, cpioMime:
		return newRPMHandler()
	default:
		if isGenericArchive {
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
	reader io.Reader,
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

	mimeT := mimeType(rdr.mime.String())
	config := newFileHandlingConfig(options...)
	if config.skipArchives && rdr.isGenericArchive {
		ctx.Logger().V(5).Info("skipping archive file", "mime", mimeT)
		return nil
	}

	handler := selectHandler(mimeT, rdr.isGenericArchive)
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
