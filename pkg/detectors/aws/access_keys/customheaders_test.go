package access_keys

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

// captureHTTPClient implements config.HTTPClient. It records the outbound
// request and returns a canned 401 response so the AWS SDK's deserialization
// path completes without a real network call.
type captureHTTPClient struct {
	captured *http.Request
}

func (c *captureHTTPClient) Do(req *http.Request) (*http.Response, error) {
	c.captured = req.Clone(req.Context())
	body := `<ErrorResponse><Error><Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid.</Message></Error></ErrorResponse>`
	return &http.Response{
		StatusCode: http.StatusForbidden,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"text/xml"}},
		Request:    req,
	}, nil
}

// resetCustomHeaders clears the global CustomHeaders state for a test and
// restores it on cleanup. Tests using this helper must not run in parallel
// since they share global feature state.
func resetCustomHeaders(t *testing.T) {
	t.Helper()
	feature.CustomHeaders.Store(http.Header{})
	t.Cleanup(func() { feature.CustomHeaders.Store(http.Header{}) })
}

// TestApplyCustomHeadersMiddleware_STSVerification confirms that
// --header values reach the wire on AWS STS verification requests.
// Because aws-sdk-go-v2 builds its own HTTP transport stack, the global
// http.DefaultTransport wrap does not cover this path; coverage is
// provided by applyCustomHeadersMiddleware on the SDK client.
func TestApplyCustomHeadersMiddleware_STSVerification(t *testing.T) {
	resetCustomHeaders(t)
	feature.CustomHeaders.Store(http.Header{
		"X-Scanner-Id": []string{"trufflehog-ci-1234"},
		"User-Agent":   []string{"OverrideUA"},
	})

	capture := &captureHTTPClient{}
	s := scanner{verificationClient: capture}

	// Verification is expected to fail (the canned 403 simulates an
	// invalid token); we only care about what reached the wire.
	_, _, _ = s.verifyMatch(context.Background(),
		"AKIAxxxxxxxxxxxxxxxx",
		"trufflehogjunkkeyforheadertestingonly1234",
		false,
	)

	require.NotNil(t, capture.captured, "AWS SDK should have invoked the injected HTTPClient")
	assert.Equal(t, "trufflehog-ci-1234", capture.captured.Header.Get("X-Scanner-Id"),
		"custom header from feature.CustomHeaders should reach the wire")
	assert.Equal(t, "OverrideUA", capture.captured.Header.Get("User-Agent"),
		"user-supplied User-Agent should fully override the default via Set semantics")
	assert.Len(t, capture.captured.Header.Values("User-Agent"), 1,
		"User-Agent should not be stacked")
}

// TestApplyCustomHeadersMiddleware_NoHeadersConfigured confirms the AWS
// path is unaffected when --header is not in use: only the default
// User-Agent set by replaceUserAgentMiddleware is present, with no other
// headers leaked.
func TestApplyCustomHeadersMiddleware_NoHeadersConfigured(t *testing.T) {
	resetCustomHeaders(t)

	capture := &captureHTTPClient{}
	s := scanner{verificationClient: capture}

	_, _, _ = s.verifyMatch(context.Background(),
		"AKIAxxxxxxxxxxxxxxxx",
		"trufflehogjunkkeyforheadertestingonly1234",
		false,
	)

	require.NotNil(t, capture.captured)
	assert.Empty(t, capture.captured.Header.Get("X-Scanner-Id"),
		"no custom header should be present when --header is not configured")
	assert.Equal(t, "TruffleHog", capture.captured.Header.Get("User-Agent"),
		"default TruffleHog User-Agent should be present")
}
