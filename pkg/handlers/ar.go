package handlers

import (
	"errors"
	"fmt"
	"io"
	"time"

	"pault.ag/go/debian/deb"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

// arHandler handles AR archive formats.
type arHandler struct{ *defaultHandler }

// newARHandler creates an arHandler.
func newARHandler() *arHandler {
	return &arHandler{defaultHandler: newDefaultHandler(arHandlerType)}
}

// HandleFile processes AR formatted files. This function needs to be implemented to extract or
// manage data from AR files according to specific requirements.
func (h *arHandler) HandleFile(ctx logContext.Context, input fileReader) chan DataOrErr {
	dataOrErrChan := make(chan DataOrErr, defaultBufferSize)

	if feature.ForceSkipArchives.Load() {
		close(dataOrErrChan)
		return dataOrErrChan
	}

	go func() {
		defer close(dataOrErrChan)

		// Defer a panic recovery to handle any panics that occur during the AR processing.
		defer func() {
			if r := recover(); r != nil {
				var panicErr error
				if e, ok := r.(error); ok {
					panicErr = e
				} else {
					panicErr = fmt.Errorf("panic occurred: %v", r)
				}
				ctx.Logger().Error(panicErr, "Panic occurred when attempting to open ar archive")
			}
		}()

		start := time.Now()
		arReader, err := deb.LoadAr(input)
		if err != nil {
			ctx.Logger().Error(err, "Error loading AR file")
			return
		}

		err = h.processARFiles(ctx, arReader, dataOrErrChan)
		if err == nil {
			h.metrics.incFilesProcessed()
		}

		// Update the metrics for the file processing and handle any errors.
		h.measureLatencyAndHandleErrors(ctx, start, err, dataOrErrChan)
	}()

	return dataOrErrChan
}

func (h *arHandler) processARFiles(ctx logContext.Context, reader *deb.Ar, dataOrErrChan chan DataOrErr) error {
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

			fileSize := arEntry.Size
			fileCtx := logContext.WithValues(ctx, "filename", arEntry.Name, "size", fileSize)

			rdr, err := newMimeTypeReader(arEntry.Data)
			if err != nil {
				return fmt.Errorf("error creating mime-type reader: %w", err)
			}

			if err := h.handleNonArchiveContent(fileCtx, rdr, dataOrErrChan); err != nil {
				fileCtx.Logger().Error(err, "error handling archive content in AR")
				h.metrics.incErrors()
			}

			h.metrics.incFilesProcessed()
			h.metrics.observeFileSize(fileSize)
		}
	}
}
