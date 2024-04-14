package handlers

import (
	"errors"
	"fmt"
	"io"

	"github.com/sassoftware/go-rpmutils"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// RPMHandler specializes DefaultHandler to manage RPM package files. It leverages shared behaviors
// from DefaultHandler and introduces additional logic specific to RPM packages.
type RPMHandler struct{ *DefaultHandler }

// HandleFile processes RPM formatted files. Further implementation is required to appropriately
// handle RPM specific archive operations.
func (h *RPMHandler) HandleFile(ctx logContext.Context, input io.Reader) (chan []byte, error) {
	archiveChan := make(chan []byte, defaultBufferSize)

	go func() {
		ctx, cancel := logContext.WithTimeout(ctx, maxTimeout)
		defer cancel()
		defer close(archiveChan)

		rpm, err := rpmutils.ReadRpm(input)
		if err != nil {
			ctx.Logger().Error(err, "error reading RPM")
			return
		}

		reader, err := rpm.PayloadReaderExtended()
		if err != nil {
			ctx.Logger().Error(err, "error getting RPM payload reader")
			return
		}

		for {
			select {
			case <-ctx.Done():
				return
			default:
				if err := h.processRPMFiles(ctx, reader, archiveChan); err != nil {
					ctx.Logger().Error(err, "error processing RPM files")
				}
			}
		}
	}()

	return archiveChan, nil
}

func (h *RPMHandler) processRPMFiles(ctx logContext.Context, reader rpmutils.PayloadReader, archiveChan chan []byte) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			fileInfo, err := reader.Next()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return fmt.Errorf("error reading RPM payload: %w", err)
			}
			fileCtx := logContext.WithValues(ctx, "filename", fileInfo.Name, "size", fileInfo.Size)

			if err := h.handleNonArchiveContent(fileCtx, reader, archiveChan); err != nil {
				fileCtx.Logger().Error(err, "error handling archive content in RPM")
			}
		}
	}
}
