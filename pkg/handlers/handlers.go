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
		for {
			select {
			case data := <-handlerChan:
				chunk := *chunkSkel
				chunk.Data = data
				chunksChan <- &chunk
			case <-ctx.Done():
				break
			}
			if handlerChan == nil {
				break
			}
		}
		return true
	}
	return false
}
