package handlers

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sassoftware/go-rpmutils"
	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// rpmHandler specializes defaultHandler to manage RPM package files. It leverages shared behaviors
// from defaultHandler and introduces additional logic specific to RPM packages.
type rpmHandler struct {
	*defaultHandler
	metrics *metrics
}

// newRPMHandler creates an rpmHandler with the provided metrics.
func newRPMHandler() *rpmHandler {
	return &rpmHandler{
		defaultHandler: newDefaultHandler(rpmHandlerType),
		metrics:        newHandlerMetrics(rpmHandlerType),
	}
}

// HandleFile processes RPM formatted files. Further implementation is required to appropriately
// handle RPM specific archive operations.
func (h *rpmHandler) HandleFile(ctx logContext.Context, input *diskbufferreader.DiskBufferReader) (chan []byte, error) {
	archiveChan := make(chan []byte, defaultBufferSize)

	go func() {
		ctx, cancel := logContext.WithTimeout(ctx, maxTimeout)
		defer cancel()
		defer close(archiveChan)

		defer func(start time.Time) {
			h.metrics.observeHandleFileLatency(time.Since(start).Microseconds())
		}(time.Now())

		rpm, err := rpmutils.ReadRpm(input)
		if err != nil {
			ctx.Logger().Error(err, "error reading RPM")
			return
		}

		reader, err := rpm.PayloadReaderExtended()
		if err != nil {
			ctx.Logger().Error(err, "error getting RPM payload reader")
			h.metrics.incErrors()
			return
		}

		if err := h.processRPMFiles(ctx, reader, archiveChan); err != nil {
			ctx.Logger().Error(err, "error processing RPM files")
			h.metrics.incErrors()
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
			fileCtx := logContext.WithValues(ctx, "filename", fileInfo.Name, "size", fileInfo.Size)

			if err := h.handleNonArchiveContent(fileCtx, reader, archiveChan); err != nil {
				fileCtx.Logger().Error(err, "error handling archive content in RPM")
				h.metrics.incErrors()
			}

			h.metrics.incFilesProcessed()
		}
	}
}
