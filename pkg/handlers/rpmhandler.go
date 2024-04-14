package handlers

import (
	"errors"
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
			fileInfo, err := reader.Next()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				ctx.Logger().Error(err, "error reading RPM payload")
				return
			}
			ctx := logContext.WithValues(ctx, "filename", fileInfo.Name, "size", fileInfo.Size)

			if err := h.handleNonArchiveContent(ctx, reader, archiveChan); err != nil {
				ctx.Logger().Error(err, "error handling archive content in RPM")
			}
		}
	}()

	return archiveChan, nil
}
