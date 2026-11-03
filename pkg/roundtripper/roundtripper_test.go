package roundtripper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
