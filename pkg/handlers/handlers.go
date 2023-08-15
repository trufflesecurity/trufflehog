package handlers

import (
	"context"
	"io"

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
	HandleSpecialized(context.Context, io.Reader) (io.Reader, bool, error)
}

type Handler interface {
	FromFile(context.Context, io.Reader) chan ([]byte)
	IsFiletype(context.Context, io.Reader) (io.Reader, bool)
	New()
}

// HandleFile processes a given file by selecting an appropriate handler from DefaultHandlers.
// It first checks if the handler implements SpecializedHandler for any special processing,
// then falls back to regular file type handling. If successful, it reads the file in chunks,
// packages them in the provided chunk skeleton, and sends them to chunksChan.
// The function returns true if processing was successful and false otherwise.
// Context is used for cancellation, and the caller is responsible for canceling it if needed.
func HandleFile(ctx context.Context, file io.Reader, chunkSkel *sources.Chunk, chunksChan chan *sources.Chunk) bool {
	for _, h := range DefaultHandlers() {
		h.New()
		var (
			isSpecial bool
			err       error
		)

		// Check if the handler implements SpecializedHandler and process accordingly.
		if specialHandler, ok := h.(SpecializedHandler); ok {
			if file, isSpecial, err = specialHandler.HandleSpecialized(ctx, file); isSpecial && err == nil {
				return handleChunks(ctx, h.FromFile(ctx, file), chunkSkel, chunksChan)
			}
		}

		var isType bool
		if file, isType = h.IsFiletype(ctx, file); isType {
			return handleChunks(ctx, h.FromFile(ctx, file), chunkSkel, chunksChan)
		}
	}
	return false
}

func handleChunks(ctx context.Context, handlerChan chan []byte, chunkSkel *sources.Chunk, chunksChan chan *sources.Chunk) bool {
	for {
		select {
		case data, open := <-handlerChan:
			if !open {
				return true
			}
			chunk := *chunkSkel
			chunk.Data = data
			select {
			case chunksChan <- &chunk:
			case <-ctx.Done():
				return false
			}
		case <-ctx.Done():
			return false
		}
	}
}
