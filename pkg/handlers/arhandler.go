package handlers

import (
	"errors"
	"fmt"
	"io"
	"time"

	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"
	"pault.ag/go/debian/deb"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// arHandler specializes defaultHandler to handle AR archive formats. By embedding defaultHandler,
// arHandler inherits and can further customize the common handling behavior such as skipping binaries.
type arHandler struct {
	*defaultHandler
	metrics *metrics
}

// newARHandler creates an arHandler with the provided metrics.
func newARHandler() *arHandler {
	return &arHandler{
		defaultHandler: newDefaultHandler(arHandlerType),
		metrics:        newHandlerMetrics(arHandlerType),
	}
}

// HandleFile processes AR formatted files. This function needs to be implemented to extract or
// manage data from AR files according to specific requirements.
func (h *arHandler) HandleFile(ctx logContext.Context, input *diskbufferreader.DiskBufferReader) (chan []byte, error) {
	archiveChan := make(chan []byte, defaultBufferSize)

	go func() {
		ctx, cancel := logContext.WithTimeout(ctx, maxTimeout)
		defer cancel()
		defer close(archiveChan)

		defer func(start time.Time) {
			h.metrics.observeHandleFileLatency(time.Since(start).Microseconds())
		}(time.Now())

		arReader, err := deb.LoadAr(input)
		if err != nil {
			ctx.Logger().Error(err, "error reading AR")
			h.metrics.incErrors()
			return
		}

		if err := h.processARFiles(ctx, arReader, archiveChan); err != nil {
			ctx.Logger().Error(err, "error processing AR files")
			h.metrics.incErrors()
		}
	}()

	return archiveChan, nil
}

func (h *arHandler) processARFiles(ctx logContext.Context, reader *deb.Ar, archiveChan chan []byte) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			arEntry, err := reader.Next()
			if err != nil {
				if errors.Is(err, io.EOF) {
					ctx.Logger().V(3).Info("AR archive fully processed")
					return nil
				}
				return fmt.Errorf("error reading AR payload: %w", err)
			}
			fileCtx := logContext.WithValues(ctx, "filename", arEntry.Name, "size", arEntry.Size)

			if err := h.handleNonArchiveContent(fileCtx, arEntry.Data, archiveChan); err != nil {
				fileCtx.Logger().Error(err, "error handling archive content in AR")
				h.metrics.incErrors()
			}

			h.metrics.incFilesProcessed()
		}
	}
}
