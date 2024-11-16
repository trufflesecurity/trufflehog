package handlers

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sassoftware/go-rpmutils"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

// rpmHandler specializes archiveHandler to manage RPM package files.
type rpmHandler struct{ *defaultHandler }

// newRPMHandler creates an rpmHandler with the provided metrics.
func newRPMHandler() *rpmHandler {
	return &rpmHandler{defaultHandler: newDefaultHandler(rpmHandlerType)}
}

// HandleFile processes RPM formatted files.
// It returns a channel of DataOrErr that will receive either file data
// or errors encountered during processing.
//
// Fatal errors that will terminate processing include:
// - Context cancellation or deadline exceeded
// - Errors reading or uncompressing the RPM file
// - Panics during processing (wrapped as ErrProcessingFatal)
//
// Non-fatal errors that will be reported but allow processing to continue include:
// - Errors processing individual files within the RPM archive (wrapped as ErrProcessingWarning)
//
// The handler will skip processing entirely if ForceSkipArchives is enabled.
func (h *rpmHandler) HandleFile(ctx logContext.Context, input fileReader) chan DataOrErr {
	dataOrErrChan := make(chan DataOrErr, defaultBufferSize)

	if feature.ForceSkipArchives.Load() {
		close(dataOrErrChan)
		return dataOrErrChan
	}

	go func() {
		defer close(dataOrErrChan)

		// Defer a panic recovery to handle any panics that occur during the RPM processing.
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
		rpm, err := rpmutils.ReadRpm(input)
		if err != nil {
			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: reading rpm error: %v", ErrProcessingFatal, err),
			}
			return
		}

		reader, err := rpm.PayloadReaderExtended()
		if err != nil {
			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: uncompressing rpm error: %v", ErrProcessingFatal, err),
			}
			return
		}

		err = h.processRPMFiles(ctx, reader, dataOrErrChan)
		if err == nil {
			h.metrics.incFilesProcessed()
		}

		// Update the metrics for the file processing and handle any errors.
		h.measureLatencyAndHandleErrors(ctx, start, err, dataOrErrChan)
	}()

	return dataOrErrChan
}

func (h *rpmHandler) processRPMFiles(
	ctx logContext.Context,
	reader rpmutils.PayloadReader,
	dataOrErrChan chan DataOrErr,
) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			fileInfo, err := reader.Next()
			if err != nil {
				if errors.Is(err, io.EOF) {
					ctx.Logger().V(3).Info("RPM payload archive fully processed")
					return nil
				}
				return fmt.Errorf("error reading RPM payload: %w", err)
			}

			fileSize := fileInfo.Size()
			fileCtx := logContext.WithValues(ctx, "filename", fileInfo.Name, "size", fileSize)

			rdr, err := newMimeTypeReader(reader)
			if err != nil {
				return fmt.Errorf("error creating mime-type reader: %w", err)
			}

			if err := h.handleNonArchiveContent(fileCtx, rdr, dataOrErrChan); err != nil {
				dataOrErrChan <- DataOrErr{
					Err: fmt.Errorf("%w: error processing RPM archive: %v", ErrProcessingWarning, err),
				}
				h.metrics.incErrors()
			}

			h.metrics.incFilesProcessed()
			h.metrics.observeFileSize(fileSize)
		}
	}
}
