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
	FromFile(io.Reader) chan ([]byte)
	IsFiletype(io.Reader) (io.Reader, bool)
	New()
}

func HandleFile(ctx context.Context, file io.Reader, chunkSkel *sources.Chunk, chunksChan chan (*sources.Chunk)) bool {
	for _, handler := range DefaultHandlers() {
		handler.New()
		var isType bool
		file, isType = handler.IsFiletype(file)
		if !isType {
			continue
		}
		handlerChan := handler.FromFile(file)
		var closed bool
		for !closed {
			select {
			case data, open := <-handlerChan:
				if !open {
					closed = true
					break
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
		return true
	}
	return false
}
