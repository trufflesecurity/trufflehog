package docker

import (
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// registryLogTransport logs failed requests to an image registry. go-containerregistry
// only reports its own retries through a global logger, so this is where support can
// see registry errors and rate limits. It logs through the request's context, so
// image fetches must pass remote.WithContext(ctx) for the line to carry the source
// fields and follow per-source debug.
type registryLogTransport struct {
	T http.RoundTripper
}

func (t *registryLogTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.T.RoundTrip(req)
	if err != nil {
		context.AddLogger(req.Context()).Logger().V(4).Info("API request failed",
			"api", "registry",
			"method", req.Method,
			"host", req.URL.Host,
			"path", req.URL.Path,
			"error", err.Error(),
		)
		return resp, err
	}
	// a 401 on /v2/ is the normal auth challenge before a token request, so a
	// failed line there alone is not an error
	logRegistryResponse(nil, resp)
	return resp, nil
}

// logRegistryResponse logs failed registry responses the same way as the namespace
// listers' retryable client.
var logRegistryResponse = common.APIResponseLogHook("registry")
