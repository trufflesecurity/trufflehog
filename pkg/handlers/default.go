package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// defaultHandler is a handler for non-archive files.
// It is embedded in other specialized handlers to provide a consistent way of handling non-archive content
// once it has been extracted or decompressed by the specific handler.
// This allows the specialized handlers to focus on their specific archive formats while leveraging
// the common functionality provided by the defaultHandler for processing the extracted content.
type defaultHandler struct{ metrics *metrics }

// newDefaultHandler creates a defaultHandler with metrics configured based on the provided handlerType.
// The handlerType parameter is used to initialize the metrics instance with the appropriate handler type,
// ensuring that the metrics recorded within the defaultHandler methods are correctly attributed to the
// specific handler that invoked them.
func newDefaultHandler(handlerType handlerType) *defaultHandler {
	return &defaultHandler{metrics: newHandlerMetrics(handlerType)}
}

// HandleFile processes the input as either an archive or non-archive based on its content,
// utilizing a single output channel. It first tries to identify the input as an archive. If it is an archive,
// it processes it accordingly; otherwise, it handles the input as non-archive content.
// The function returns a channel that will receive the extracted data bytes and an error if the initial setup fails.
func (h *defaultHandler) HandleFile(ctx logContext.Context, input fileReader) chan DataOrErr {
	// Shared channel for archived data, non-archive data, and errors.
	dataOrErrChan := make(chan DataOrErr, defaultBufferSize)

	go func() {
		defer close(dataOrErrChan)

		start := time.Now()

		err := h.handleNonArchiveContent(ctx, newMimeTypeReaderFromFileReader(input), dataOrErrChan)
		if err == nil {
			h.metrics.incFilesProcessed()
		}

		// Update the metrics for the file processing and handle errors.
		h.measureLatencyAndHandleErrors(ctx, start, err, dataOrErrChan)
	}()

	return dataOrErrChan
}

// measureLatencyAndHandleErrors measures the latency of the file processing and updates the metrics accordingly.
// It also records errors and timeouts in the metrics.
func (h *defaultHandler) measureLatencyAndHandleErrors(
	ctx logContext.Context,
	start time.Time,
	err error,
	dataErrChan chan DataOrErr,
) {
	if err == nil {
		h.metrics.observeHandleFileLatency(time.Since(start).Milliseconds())
		return
	}
	dataOrErr := DataOrErr{}

	h.metrics.incErrors()
	if errors.Is(err, context.DeadlineExceeded) {
		h.metrics.incFileProcessingTimeouts()
		dataOrErr.Err = fmt.Errorf("%w: error processing chunk: %v", ErrProcessingFatal, err)
		if err := common.CancellableWrite(ctx, dataErrChan, dataOrErr); err != nil {
			ctx.Logger().Error(err, "error writing to data channel")
		}
		return
	}

	dataOrErr.Err = err
	if err := common.CancellableWrite(ctx, dataErrChan, dataOrErr); err != nil {
		ctx.Logger().Error(err, "error writing to data channel")
	}
}

// handleNonArchiveContent processes files that are not archives,
// serving as the final stage in the extraction/decompression pipeline.
// It manages MIME type detection, file skipping logic, and chunk-based
// reading and writing to the data channel. This function ensures
// all non-archive content is properly handled for subsequent processing.
func (h *defaultHandler) handleNonArchiveContent(
	ctx logContext.Context,
	reader mimeTypeReader,
	dataOrErrChan chan DataOrErr,
) error {
	mimeExt := reader.mimeExt

	if common.SkipFile(mimeExt) || common.IsBinary(mimeExt) {
		ctx.Logger().V(2).Info("skipping file: extension is ignored", "ext", mimeExt)
		h.metrics.incFilesSkipped()
		// Make sure we consume the reader to avoid potentially blocking indefinitely.
		_, _ = io.Copy(io.Discard, reader)
		return nil
	}

	chunkReader := sources.NewChunkReader()
	for data := range chunkReader(ctx, reader) {
		dataOrErr := DataOrErr{}
		if err := data.Error(); err != nil {
			h.metrics.incErrors()
			dataOrErr.Err = fmt.Errorf("%w: error reading chunk: %v", ErrProcessingWarning, err)
			if writeErr := common.CancellableWrite(ctx, dataOrErrChan, dataOrErr); writeErr != nil {
				return fmt.Errorf("%w: error writing to data channel: %v", ErrProcessingFatal, writeErr)
			}
			continue
		}

		dataOrErr.Data = data.Bytes()
		if err := common.CancellableWrite(ctx, dataOrErrChan, dataOrErr); err != nil {
			return err
		}
		h.metrics.incBytesProcessed(len(data.Bytes()))
	}
	return nil
}
