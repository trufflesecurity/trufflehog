package handlers

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sassoftware/go-rpmutils"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// rpmHandler specializes defaultHandler to manage RPM package files. It leverages shared behaviors
// from defaultHandler and introduces additional logic specific to RPM packages.
type rpmHandler struct{ *defaultHandler }

// newRPMHandler creates an rpmHandler.
func newRPMHandler() *rpmHandler {
	return &rpmHandler{defaultHandler: newDefaultHandler(rpmHandlerType)}
}

// HandleFile processes RPM formatted files. Further implementation is required to appropriately
// handle RPM specific archive operations.
func (h *rpmHandler) HandleFile(ctx logContext.Context, input readSeekCloser) (chan []byte, error) {
	archiveChan := make(chan []byte, defaultBufferSize)

	go func() {
		ctx, cancel := logContext.WithTimeout(ctx, maxTimeout)
		defer cancel()
		defer close(archiveChan)

		// Update the metrics for the file processing.
		start := time.Now()
		var err error
		defer h.measureLatencyAndHandleErrors(start, err)

		var rpm *rpmutils.Rpm
		rpm, err = rpmutils.ReadRpm(input)
		if err != nil {
			ctx.Logger().Error(err, "error reading RPM")
			return
		}

		var reader rpmutils.PayloadReader
		reader, err = rpm.PayloadReaderExtended()
		if err != nil {
			ctx.Logger().Error(err, "error getting RPM payload reader")
			return
		}

		if err = h.processRPMFiles(ctx, reader, archiveChan); err != nil {
			ctx.Logger().Error(err, "error processing RPM files")
		}
	}()

	return archiveChan, nil
}

func (h *rpmHandler) processRPMFiles(ctx logContext.Context, reader rpmutils.PayloadReader, archiveChan chan []byte) error {
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

			if err := h.handleNonArchiveContent(fileCtx, reader, archiveChan); err != nil {
				fileCtx.Logger().Error(err, "error handling archive content in RPM")
				h.metrics.incErrors()
			}

			h.metrics.incFilesProcessed()
			h.metrics.observeFileSize(fileSize)
		}
	}
}
