package lightweight_analyze

import (
	"io"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const (
	KeyResponse = "lwa.response"
)

// LWACopyAndCloseResponseBody copies an HTTP response body, close it, and logs any errors that occur.
//
// This is a helper function for lightweight analysis implementation in detectors.
func CopyAndCloseResponseBody(ctx context.Context, res *http.Response) []byte {
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		ctx.Logger().Error(err, "failed to read response body")
	}
	err = res.Body.Close()
	if err != nil {
		ctx.Logger().Error(err, "failed to close response body")
	}
	return resBody
}

type Fields struct {
	ID *string
	Name *string
	Email *string
	URL *string
}

func AugmentExtraData(extraData map[string]string, fields Fields) {
	var v *string

	v = fields.ID
	if v != nil {
		extraData["lwa.id"] = *v
	}

	v = fields.Name
	if v != nil {
		extraData["lwa.name"] = *v
	}

	v = fields.Email
	if v != nil {
		extraData["lwa.email"] = *v
	}

	v = fields.URL
	if v != nil {
		extraData["lwa.url"] = *v
	}
}
