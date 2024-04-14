package handlers

import (
	"io"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// ARHandler specializes DefaultHandler to handle AR archive formats. By embedding DefaultHandler,
// ARHandler inherits and can further customize the common handling behavior such as skipping binaries.
type ARHandler struct{ *DefaultHandler }

// HandleFile processes AR formatted files. This function needs to be implemented to extract or
// manage data from AR files according to specific requirements.
func (h *ARHandler) HandleFile(ctx logContext.Context, input io.Reader) (chan []byte, error) {
	// TODO implement me
	panic("implement me")
}
