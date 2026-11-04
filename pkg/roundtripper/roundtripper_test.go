package roundtripper

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/log/logtest"
)

func TestRoundTripper_DebugLogsHidePasswordInURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	// Log with debug on, the same way a source with debug: true would.
	ctx, logs := logtest.DebugContext()
	client := &http.Client{Transport: NewRoundTripper(nil, WithLogger(ctx.Logger()), WithLogging())}

	url := strings.Replace(server.URL, "http://", "http://user:hunter2@", 1)
	resp, err := client.Get(url)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	// The request is logged with its URL, but the password is hidden.
	require.Equal(t, 1, logs.FilterMessage("got response").Len())
	for _, entry := range logs.All() {
		fields := fmt.Sprint(entry.ContextMap())
		assert.Contains(t, fields, "user:xxxxx@")
		assert.NotContains(t, fields, "hunter2")
	}
}

func TestRoundTripper_CancelDuringRetryWait(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := &http.Client{Transport: NewRoundTripper(nil,
		WithRetryable(WithShouldRetry5XXDuration(30*time.Second)),
	)}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	start := time.Now()
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestRoundTripper_LogsWithWrappedRequestContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	// A client Timeout makes net/http wrap the request ctx in a plain context.
	// The lines must still use the ctx logger, not the discarding fallback.
	ctx, logs := logtest.SourceContext(true)
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: NewRoundTripper(nil, WithLogger(logr.Discard()), WithLogging()),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	logtest.CheckSourceLines(t, logs.All())
}

// closeTracker counts how many response bodies were closed.
type closeTracker struct {
	original http.RoundTripper
	closed   atomic.Int32
}

func (c *closeTracker) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.original.RoundTrip(req)
	if resp != nil {
		resp.Body = &trackedBody{ReadCloser: resp.Body, closed: &c.closed}
	}
	return resp, err
}

type trackedBody struct {
	io.ReadCloser
	closed *atomic.Int32
}

func (b *trackedBody) Close() error {
	b.closed.Add(1)
	return b.ReadCloser.Close()
}

func TestRoundTripper_ClosesBodyBeforeRetry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	tracker := &closeTracker{original: http.DefaultTransport}
	client := &http.Client{Transport: NewRoundTripper(tracker,
		WithRetryable(WithShouldRetry5XXDuration(time.Millisecond)),
	)}

	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// The 500 was closed before the retry. The 200 is still open for the caller.
	assert.EqualValues(t, 1, tracker.closed.Load())
	require.NoError(t, resp.Body.Close())
	assert.EqualValues(t, 2, tracker.closed.Load())
}
