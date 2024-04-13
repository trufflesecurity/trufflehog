package handlers

import (
	"io"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// RPMHandler specializes DefaultHandler to manage RPM package files. It leverages shared behaviors
// from DefaultHandler and introduces additional logic specific to RPM packages.
type RPMHandler struct{ DefaultHandler }

// HandleFile processes RPM formatted files. Further implementation is required to appropriately
// handle RPM specific archive operations.
func (h *RPMHandler) HandleFile(ctx logContext.Context, input io.Reader) (chan []byte, error) {
	// TODO implement me
	panic("implement me")
}
