package elasticsearch

import (
	"net/http"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// apiLogger is an elastictransport.Logger. The ES client retries 502, 503, 504 and
// network errors on its own and logs nothing, so without it support can't see retries
// or failed calls. The client calls it once per attempt, and passes an empty response
// when the attempt got none, so err must be checked first. It logs through the
// request's context, so every request must carry the scan ctx. Headers, bodies and the
// full URL are never logged, they can hold credentials or document data.
type apiLogger struct{}

func (apiLogger) LogRoundTrip(req *http.Request, res *http.Response, err error, _ time.Time, dur time.Duration) error {
	if req == nil {
		return nil
	}
	logger := context.AddLogger(req.Context()).Logger()
	// A network error, like connection refused or a timeout. Only the last one
	// reaches the caller, so retried ones are only visible here. It is logged as
	// a field, since V(4).Error would ignore the level.
	if err != nil {
		logger.V(4).Info("Elasticsearch request failed",
			"method", req.Method,
			"path", req.URL.Path,
			"duration", dur,
			"error", err.Error(),
		)
		return nil
	}
	if res == nil {
		return nil
	}
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
