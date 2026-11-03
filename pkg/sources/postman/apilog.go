package postman

import (
	"net/http"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	trContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// withAPILogHooks logs retries and failed responses from the Postman API. The client
// retries 429 and 5xx on its own, so without these hooks support can't see them. The
// hooks log through the request's context, so every request must carry the scan ctx.
func withAPILogHooks() common.ClientOption {
	return func(c *retryablehttp.Client) {
		c.RequestLogHook = logAPIRetry
		c.ResponseLogHook = logAPIResponse
	}
}

// logAPIRetry is a retryablehttp.RequestLogHook. It runs before every attempt and
// logs the ones that are retries.
func logAPIRetry(_ retryablehttp.Logger, req *http.Request, attempt int) {
	if attempt == 0 {
		return
	}
	trContext.AddLogger(req.Context()).Logger().V(4).Info("Retrying Postman API request",
		"path", req.URL.Path,
		"attempt", attempt,
	)
}

// logAPIResponse is a retryablehttp.ResponseLogHook. It logs failed responses,
// including the ones that will be retried. Headers are not logged, they can hold
// cookies or tokens.
func logAPIResponse(_ retryablehttp.Logger, resp *http.Response) {
	if resp.StatusCode < 400 {
		return
	}
	trContext.AddLogger(resp.Request.Context()).Logger().V(4).Info("Postman API request failed",
		"path", resp.Request.URL.Path,
		"status", resp.StatusCode,
		"retry_after", resp.Header.Get("Retry-After"),
	)
}
