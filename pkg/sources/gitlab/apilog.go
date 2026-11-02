package gitlab

import (
	"net/http"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// logAPIRequest is a retryablehttp.RequestLogHook. It runs before every attempt
// and logs the ones that are retries. It logs through the request's context, so
// API calls must pass gitlab.WithContext(ctx) for the line to carry the source
// fields and follow per-source debug.
func logAPIRequest(_ retryablehttp.Logger, req *http.Request, attempt int) {
	if attempt == 0 {
		return
	}
	context.AddLogger(req.Context()).Logger().V(4).Info("Retrying GitLab API request",
		"method", req.Method,
		"path", req.URL.Path,
		"attempt", attempt,
	)
}

// logAPIResponse is a retryablehttp.ResponseLogHook. It logs every response that
// is not a 2xx, which covers permission errors, rate limits and server errors.
// Only the path is logged, not the query.
func logAPIResponse(_ retryablehttp.Logger, resp *http.Response) {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return
	}
	context.AddLogger(resp.Request.Context()).Logger().V(4).Info("GitLab API request failed",
		"method", resp.Request.Method,
		"path", resp.Request.URL.Path,
		"status", resp.StatusCode,
		"retry_after", resp.Header.Get("Retry-After"),
		"ratelimit_remaining", resp.Header.Get("Ratelimit-Remaining"),
	)
}
