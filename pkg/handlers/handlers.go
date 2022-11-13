package handlers

import (
	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func DefaultHandlers(ctx context.Context) []Handler {
	handlers := []Handler{}

	tika := NewTika(WithLogger(ctx.Logger()))

	if tika != nil {
		handlers = append(handlers, tika)
	}

	handlers = append(handlers, &Archive{})

	return handlers
}

type Handler interface {
	FromFile(*diskbufferreader.DiskBufferReader) chan ([]byte)
	IsFiletype(*diskbufferreader.DiskBufferReader) bool
	New()
}

func HandleFile(ctx context.Context, file *diskbufferreader.DiskBufferReader, chunkSkel *sources.Chunk, chunksChan chan (*sources.Chunk)) bool {
	// Find a handler for this file.

	defer func() {
		err := file.Reset()
		if err != nil {
			ctx.Logger().Error(err, "error resetting file")
		}
	}()
	var handler Handler
	for _, h := range DefaultHandlers(ctx) {
		h.New()
		var isType bool
		if isType = h.IsFiletype(file); isType {
			handler = h
			break
		}
	}
	if handler == nil {
		return false
	}

	err := file.Reset()
	if err != nil {
		ctx.Logger().Error(err, "error resetting file")
		return false
	}

	// Process the file and read all []byte chunks from handlerChan.
	handlerChan := handler.FromFile(file)
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
