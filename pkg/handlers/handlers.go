package handlers

import (
	"context"
	"io"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// DefaultHandlers returns all the default handlers.
func DefaultHandlers() []Handler {
	return []Handler{
		&Archive{},
	}
}

// Handler is responsible for extracting data from a file.
type Handler interface {
	// FromFile takes in a file and returns a channel of bytes that are
	// extracted from the file.
	FromFile(context.Context, io.Reader) chan []byte
	// IsFiletype takes in a file and returns whether the file is of the
	// given type.
	IsFiletype(context.Context, io.Reader) (io.Reader, bool)
	// New creates a new handler.
	New()
}

// HandleFile takes in different file types and extracts the data from them.
// It sends the chunked data on the chunksChan.
// It returns true if the file was handled, false otherwise.
func HandleFile(ctx context.Context, file io.Reader, chunkSkel *sources.Chunk, chunksChan chan *sources.Chunk) bool {
	// Find a handler for this file.
	var handler Handler
	for _, h := range DefaultHandlers() {
		h.New()
		var isType bool
		if file, isType = h.IsFiletype(ctx, file); isType {
			handler = h
			break
		}
	}
	if handler == nil {
		return false
	}

	// Process the file and read all []byte chunks from handlerChan.
	handlerChan := handler.FromFile(ctx, file)
	for data := range handlerChan {
		chunk := *chunkSkel
		chunk.Data = data

		if common.IsDone(ctx) {
			return false
		}
		// Send data on chunksChan.
		chunksChan <- &chunk
	}
	return true
}
