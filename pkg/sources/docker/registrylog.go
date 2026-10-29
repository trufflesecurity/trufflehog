package docker

import (
	"net/http"

	"github.com/hashicorp/go-retryablehttp"

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
		context.AddLogger(req.Context()).Logger().V(4).Info("Registry request failed",
			"method", req.Method,
			"host", req.URL.Host,
			"path", req.URL.Path,
			"error", err.Error(),
		)
		return resp, err
	}
	// a 401 on /v2/ is the normal auth challenge before a token request, so a
	// failed line there alone is not an error
	if resp.StatusCode >= 400 {
		logRegistryResponse(resp)
	}
	return resp, nil
}

// withRegistryLogHooks adds the retry and response hooks to the client the registry
// listers use.
func withRegistryLogHooks() common.ClientOption {
	return func(c *retryablehttp.Client) {
		c.RequestLogHook = logRegistryRetry
		c.ResponseLogHook = func(_ retryablehttp.Logger, resp *http.Response) {
			if resp.StatusCode >= 400 {
				logRegistryResponse(resp)
			}
		}
	}
}

// logRegistryRetry is a retryablehttp.RequestLogHook. It runs before every attempt
// and logs the ones that are retries.
func logRegistryRetry(_ retryablehttp.Logger, req *http.Request, attempt int) {
	if attempt == 0 {
		return
	}
	context.AddLogger(req.Context()).Logger().V(4).Info("Retrying registry API request",
		"method", req.Method,
		"host", req.URL.Host,
		"path", req.URL.Path,
		"attempt", attempt,
	)
}

// logRegistryResponse logs a failed registry response. Only the path is logged,
// not the query, since token requests carry the scope there.
func logRegistryResponse(resp *http.Response) {
	context.AddLogger(resp.Request.Context()).Logger().V(4).Info("Registry request failed",
		"method", resp.Request.Method,
		"host", resp.Request.URL.Host,
		"path", resp.Request.URL.Path,
		"status", resp.StatusCode,
		"retry_after", resp.Header.Get("Retry-After"),
	)
}
