package handlers

import (
	"io"

	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func DefaultHandlers() []Handler {
	return []Handler{
		&Archive{},
	}
}

// SpecializedHandler defines the interface for handlers that can process specialized archives.
// It includes a method to handle specialized archives and determine if the file is of a special type.
type SpecializedHandler interface {
	// HandleSpecialized examines the provided file reader within the context and determines if it is a specialized archive.
	// It returns a reader with any necessary modifications, a boolean indicating if the file was specialized,
	// and an error if something went wrong during processing.
	HandleSpecialized(logContext.Context, io.Reader) (io.Reader, bool, error)
}

// Option is a function type that applies a configuration to a Handler.
type Option func(Handler)

// WithSkipBinaries returns a Option that configures whether to skip binary files.
func WithSkipBinaries(skip bool) Option {
	return func(h Handler) {
		if a, ok := h.(*Archive); ok {
			a.skipBinaries = skip
		}
	}
}

// WithSkipArchives returns a Option that configures whether to skip archive files.
func WithSkipArchives(skip bool) Option {
	return func(h Handler) {
		if a, ok := h.(*Archive); ok {
			a.skipArchives = skip
		}
	}
}

type Handler interface {
	FromFile(logContext.Context, io.Reader) chan []byte
	IsFiletype(logContext.Context, io.Reader) (io.Reader, bool)
	New(...Option)
}

// HandleFile processes a given file by selecting an appropriate handler from DefaultHandlers.
// It first checks if the handler implements SpecializedHandler for any special processing,
// then falls back to regular file type handling. If successful, it reads the file in chunks,
// packages them in the provided chunk skeleton, and reports them to the chunk reporter.
// The function returns true if processing was successful and false otherwise.
// Context is used for cancellation, and the caller is responsible for canceling it if needed.
func HandleFile(ctx logContext.Context, reReader *diskbufferreader.DiskBufferReader, chunkSkel *sources.Chunk, reporter sources.ChunkReporter, opts ...Option) bool {
	for _, h := range DefaultHandlers() {
		h.New(opts...)

		if handled := processHandler(ctx, h, reReader, chunkSkel, reporter); handled {
			return true
		}
	}

	return false
}

func processHandler(ctx logContext.Context, h Handler, reReader *diskbufferreader.DiskBufferReader, chunkSkel *sources.Chunk, reporter sources.ChunkReporter) bool {
	if specialHandler, ok := h.(SpecializedHandler); ok {
		file, isSpecial, err := specialHandler.HandleSpecialized(ctx, reReader)
		if isSpecial {
			return handleChunks(ctx, h.FromFile(ctx, file), chunkSkel, reporter)
		}
		if err != nil {
			ctx.Logger().Error(err, "error handling file")
		}
	}

	if _, err := reReader.Seek(0, io.SeekStart); err != nil {
		ctx.Logger().Error(err, "error seeking to start of file")
		return false
	}

	if _, isType := h.IsFiletype(ctx, reReader); !isType {
		return false
	}

	return handleChunks(ctx, h.FromFile(ctx, reReader), chunkSkel, reporter)
}

func handleChunks(ctx logContext.Context, handlerChan chan []byte, chunkSkel *sources.Chunk, reporter sources.ChunkReporter) bool {
	if handlerChan == nil {
		return false
	}

	for {
		select {
		case data, open := <-handlerChan:
			if !open {
				return true
			}
			chunk := *chunkSkel
			chunk.Data = data
			if err := reporter.ChunkOk(ctx, chunk); err != nil {
				return false
			}
		case <-ctx.Done():
			return false
		}
	}
}
