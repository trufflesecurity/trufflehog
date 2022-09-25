package handlers

import (
	"io"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// DefaultHandlers returns the default set of handlers.
func DefaultHandlers() []Handler {
	return []Handler{
		&Archive{},
	}
}

// Handler is responsible for handling a specific filetype.
type Handler interface {
	FromFile(io.Reader) chan ([]byte)
	IsFiletype(io.Reader) (io.Reader, bool)
	New()
}

// HandleFile will return true if the file was handled by one of the DefaultHandlers.
// Otherwise, it will return false.
func HandleFile(file io.Reader, chunkSkel *sources.Chunk, chunksChan chan *sources.Chunk) bool {
	for _, handler := range DefaultHandlers() {
		handler.New()
		var isType bool
		file, isType = handler.IsFiletype(file)
		if !isType {
			continue
		}
		handlerChan := handler.FromFile(file)
		for data := range handlerChan {
			chunk := *chunkSkel
			chunk.Data = data
			chunksChan <- &chunk
		}
		return true
	}
	return false
}
