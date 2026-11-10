package common

import (
	"net/http"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// WithAPILogHooks logs retries and failed responses of a retryable client at V(4).
// retryablehttp retries 429 and 5xx on its own and logs nothing, so without these
// hooks support can't see retries, rate limits or API errors. api names the service
// in the "api" field, like "circleci".
//
// The hooks log through the request's context, so every request must carry the
// scan ctx (http.NewRequestWithContext, or the client library's ctx option) for the
// line to have the source fields and follow per-source debug.
func WithAPILogHooks(api string) ClientOption {
	return func(c *retryablehttp.Client) {
		c.RequestLogHook = APIRequestLogHook(api)
		c.ResponseLogHook = APIResponseLogHook(api)
	}
}

// APIRequestLogHook is the request hook of WithAPILogHooks, for clients that take
// hooks one by one. It runs before every attempt and logs the ones that are retries.
func APIRequestLogHook(api string) retryablehttp.RequestLogHook {
	return func(_ retryablehttp.Logger, req *http.Request, attempt int) {
		if attempt == 0 {
			return
		}
		context.AddLogger(req.Context()).Logger().V(4).Info("Retrying API request",
			"api", api,
			"method", req.Method,
			"host", req.URL.Host,
			"path", req.URL.Path,
			"attempt", attempt,
		)
	}
}

// APIResponseLogHook is the response hook of WithAPILogHooks. It logs responses of
// 400 and above, including the ones that will be retried. Only the host and path
// are logged: headers can hold tokens or cookies, and the query can hold signatures.
func APIResponseLogHook(api string) retryablehttp.ResponseLogHook {
	return func(_ retryablehttp.Logger, resp *http.Response) {
		if resp.StatusCode < 400 {
			return
		}
		context.AddLogger(resp.Request.Context()).Logger().V(4).Info("API request failed",
			"api", api,
			"method", resp.Request.Method,
			"host", resp.Request.URL.Host,
			"path", resp.Request.URL.Path,
			"status", resp.StatusCode,
			"retry_after", resp.Header.Get("Retry-After"),
			"ratelimit_remaining", rateLimitRemaining(resp.Header),
		)
	}
}

// rateLimitRemaining reads the remaining request count, which APIs send under one of
// two header names.
func rateLimitRemaining(h http.Header) string {
	if v := h.Get("RateLimit-Remaining"); v != "" {
		return v
	}
	return h.Get("X-RateLimit-Remaining")
}
