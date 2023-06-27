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

type Handler interface {
	FromFile(context.Context, io.Reader) chan ([]byte)
	IsFiletype(context.Context, io.Reader) (io.Reader, bool)
	New()
}

func HandleFile(ctx context.Context, file io.Reader, chunkSkel *sources.Chunk, chunksChan chan (*sources.Chunk)) bool {
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
	for {
		select {
		case data, open := <-handlerChan:
			if !open {
				// We finished reading everything from handlerChan.
				return true
			}
			chunk := *chunkSkel
			chunk.Data = data
			// Send data on chunksChan.
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
