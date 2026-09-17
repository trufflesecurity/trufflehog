package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestEmbeddedEndpointSetter(t *testing.T) {
	type Scanner struct{ EndpointSetter }

	var s Scanner

	t.Run("useFoundEndpoints is true", func(t *testing.T) {
		s.useFoundEndpoints = true

		// "baz" is passed to Endpoints, should appear in the result
		assert.Equal(t, []string{"baz"}, s.Endpoints("baz"))
	})

	t.Run("setting configured endpoints", func(t *testing.T) {
		// Setting "foo" and "bar"
		assert.NoError(t, s.SetConfiguredEndpoints("foo", "bar"))

		// Returning error because no endpoints are passed
		assert.Error(t, s.SetConfiguredEndpoints())
	})

	// "foo" and "bar" are added as configured endpoint

	t.Run("useFoundEndpoints adds new endpoints", func(t *testing.T) {
		// "baz" is added because useFoundEndpoints is true
		assert.Equal(t, []string{"foo", "bar", "baz"}, s.Endpoints("baz"))
	})

	t.Run("useCloudEndpoint is true", func(t *testing.T) {
		s.useCloudEndpoint = true
		s.cloudEndpoint = "test"

		// "test" is added because useCloudEndpoint is true and cloudEndpoint is set
		assert.Equal(t, []string{"foo", "bar", "test"}, s.Endpoints())
	})

	t.Run("disable both foundEndpoints and cloudEndpoint", func(t *testing.T) {
		// now disable both useFoundEndpoints and useCloudEndpoint
		s.useFoundEndpoints = false
		s.useCloudEndpoint = false

		// "test" won't be added
		assert.Equal(t, []string{"foo", "bar"}, s.Endpoints("test"))
	})

	t.Run("cloudEndpoint not added when useCloudEndpoint is false", func(t *testing.T) {
		s.cloudEndpoint = "new"

		// "new" is not added because useCloudEndpoint is false
		assert.Equal(t, []string{"foo", "bar"}, s.Endpoints())
	})

}

// ─── OAuth2 token source on EndpointSetter ───────────────────────────

func TestEndpointSetter_OAuth2(t *testing.T) {
	t.Parallel()

	var s EndpointSetter

	t.Run("HasOAuth2 is false by default", func(t *testing.T) {
		assert.False(t, s.HasOAuth2())
		assert.Nil(t, s.OAuth2TokenSource())
	})

	t.Run("SetOAuth2TokenSource and HasOAuth2", func(t *testing.T) {
		fakeTS := &fakeTokenSource{}
		s.SetOAuth2TokenSource(fakeTS)
		assert.True(t, s.HasOAuth2())
		assert.Equal(t, fakeTS, s.OAuth2TokenSource())
	})

	t.Run("SetOAuth2TokenSource nil clears it", func(t *testing.T) {
		s.SetOAuth2TokenSource(nil)
		assert.False(t, s.HasOAuth2())
		assert.Nil(t, s.OAuth2TokenSource())
	})
}

// TestEndpointSetter_OAuth2_DisablesCloudAndFound verifies the credential-
// leakage guard: when an OAuth2 token source is configured, cloud and found
// endpoints are automatically disabled so Bearer tokens only travel to the
// explicitly configured verification endpoints.
func TestEndpointSetter_OAuth2_DisablesCloudAndFound(t *testing.T) {
	var s EndpointSetter
	s.useCloudEndpoint = true
	s.useFoundEndpoints = true

	// Setting a non-nil token source must disable both flags.
	s.SetOAuth2TokenSource(&fakeTokenSource{})
	assert.False(t, s.useCloudEndpoint, "useCloudEndpoint should be disabled after setting OAuth2 source")
	assert.False(t, s.useFoundEndpoints, "useFoundEndpoints should be disabled after setting OAuth2 source")

	// Setting nil restores nothing (flags stay as-is); callers must
	// re-enable explicitly.
	s.SetOAuth2TokenSource(nil)
	assert.False(t, s.useCloudEndpoint, "useCloudEndpoint should remain false after nil source")
	assert.False(t, s.useFoundEndpoints, "useFoundEndpoints should remain false after nil source")
}

// fakeTokenSource satisfies OAuth2TokenSource for tests.
type fakeTokenSource struct{}

func (f *fakeTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: "fake"}, nil
}

// ─── TracedTokenSource ───────────────────────────────────────────────

func TestTracedTokenSource_EnrichContext(t *testing.T) {
	t.Parallel()

	ts := &TracedTokenSource{
		TokenSource: &fakeTokenSource{},
		Trace:       "abc123",
	}

	ctx := ts.EnrichContext(logContext.Background())

	// The trace should appear as a structured log field. Extract it
	// by logging and checking the logger's key-value pairs.
	// Since logContext.WithValue uses the structured logger's key store,
	// the simplest verification is a round-trip through the context.
	got := ctx.Value("oauth2_trace")
	assert.Equal(t, "abc123", got)
}

func TestTracedTokenSource_DelegatesToken(t *testing.T) {
	t.Parallel()

	inner := &fakeTokenSource{}
	ts := &TracedTokenSource{
		TokenSource: inner,
		Trace:       "trace1",
	}

	tok, err := ts.Token()
	assert.NoError(t, err)
	assert.Equal(t, "fake", tok.AccessToken)
}
