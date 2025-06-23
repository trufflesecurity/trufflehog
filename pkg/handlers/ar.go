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

// HandleFile processes AR formatted files and returns a channel of DataOrErr.
// Fatal errors that will terminate processing include:
// - Context cancellation
// - Context deadline exceeded
// - Errors loading the AR file
// - Panics during processing (recovered and returned as fatal errors)
//
// Non-fatal errors that will be logged but allow processing to continue include:
// - Errors creating mime-type readers for individual AR entries
// - Errors handling content within AR entries
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
				dataOrErrChan <- DataOrErr{
					Err: fmt.Errorf("%w: panic error: %v", ErrProcessingFatal, panicErr),
				}
			}
		}()

		start := time.Now()
		arReader, err := deb.LoadAr(input)
		if err != nil {
			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: loading AR error: %v", ErrProcessingFatal, err),
			}
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
				dataOrErrChan <- DataOrErr{
					Err: fmt.Errorf("%w: error creating AR mime-type reader: %v", ErrProcessingWarning, err),
				}
				h.metrics.incErrors()
				continue
			}

			if err := h.handleNonArchiveContent(fileCtx, rdr, dataOrErrChan); err != nil {
				dataOrErrChan <- DataOrErr{
					Err: fmt.Errorf("%w: error handling archive content in AR: %v", ErrProcessingWarning, err),
				}
				h.metrics.incErrors()
				continue
			}

			h.metrics.incFilesProcessed()
			h.metrics.observeFileSize(fileSize)
		}
	}
}
