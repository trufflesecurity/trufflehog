package common

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/log/logtest"
)

func TestWithAPILogHooks(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("X-RateLimit-Remaining", "7")
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()

	ctx, logs := logtest.SourceContext(true)
	client := RetryableHTTPClientTimeout(10, WithAPILogHooks("test"), WithRetryWaitMin(0), WithRetryWaitMax(0))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/items?sig=apilogtestsignature", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer apilogtesttoken")

	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	// the failed response and the retry both log, with the source fields, and
	// never the query or the auth header
	logtest.CheckSourceLines(t, logs.All(), "apilogtestsignature", "apilogtesttoken")
	failed := logs.FilterMessage("API request failed").All()
	require.Len(t, failed, 1)
	fields := failed[0].ContextMap()
	assert.Equal(t, "test", fields["api"])
	assert.Equal(t, "/items", fields["path"])
	assert.EqualValues(t, http.StatusServiceUnavailable, fields["status"])
	assert.Equal(t, "7", fields["ratelimit_remaining"])
	assert.Equal(t, 1, logs.FilterMessage("Retrying API request").Len())
}
