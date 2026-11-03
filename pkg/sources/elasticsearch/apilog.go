package elasticsearch

import (
	"net/http"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// apiLogger is an elastictransport.Logger. The ES client retries 502, 503 and 504 on
// its own and logs nothing, so without it support can't see retries or failed calls.
// The client calls it once per attempt. It logs through the request's context, so
// every request must carry the scan ctx. Headers, bodies and the full URL are never
// logged, they can hold credentials or document data.
type apiLogger struct{}

func (apiLogger) LogRoundTrip(req *http.Request, res *http.Response, _ error, _ time.Time, dur time.Duration) error {
	// A transport error is returned to the caller, which logs it, so only
	// responses are logged here.
	if req == nil || res == nil {
		return nil
	}
	logger := context.AddLogger(req.Context()).Logger()
	if res.StatusCode >= 400 {
		logger.V(4).Info("Elasticsearch request failed",
			"method", req.Method,
			"path", req.URL.Path,
			"status", res.StatusCode,
			"duration", dur,
		)
		return nil
	}
	logger.V(5).Info("Elasticsearch request",
		"method", req.Method,
		"path", req.URL.Path,
		"status", res.StatusCode,
		"duration", dur,
	)
	return nil
}

func (apiLogger) RequestBodyEnabled() bool  { return false }
func (apiLogger) ResponseBodyEnabled() bool { return false }
