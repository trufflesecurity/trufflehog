package roundtripper

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
