package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmbeddedEndpointSetter(t *testing.T) {
	type Scanner struct{ EndpointSetter }

	var s Scanner

	t.Run("useFoundEndpoints is true", func(t *testing.T) {
		s.useFoundEndpoints = true

		// "baz" is passed to Endpoints, should appear in the result
		assert.Equal(t, []string{"baz"}, s.Endpoints([]string{"baz"}))
	})

	t.Run("setting configured endpoints", func(t *testing.T) {
		// Setting "foo" and "bar"
		assert.NoError(t, s.SetConfiguredEndpoints("foo", "bar"))

		// Returning error because no endpoints are passed
		assert.Error(t, s.SetConfiguredEndpoints())
	})

	// "foo" and "bar" are added as configured endpoint

	t.Run("useFoundEndpoints adds new endpoints", func(t *testing.T) {
		// "baz" is added because useFoundEndpoints is true, and after configured endpoints
		assert.Equal(t, []string{"foo", "bar", "baz"}, s.Endpoints([]string{"baz"}))
	})

	t.Run("useCloudEndpoints is true", func(t *testing.T) {
		s.useCloudEndpoints = true
		s.cloudEndpoints = []string{"test"}

		// "test" is added because useCloudEndpoints is true and cloudEndpoints is set,
		// and appears before found endpoints
		assert.Equal(t, []string{"foo", "bar", "test"}, s.Endpoints(nil))
	})

	t.Run("multiple cloud endpoints are all added, in order, before found endpoints", func(t *testing.T) {
		s.cloudEndpoints = []string{"cloud1", "cloud2"}

		assert.Equal(t, []string{"foo", "bar", "cloud1", "cloud2", "baz"}, s.Endpoints([]string{"baz"}))
	})

	t.Run("disable both foundEndpoints and cloudEndpoint", func(t *testing.T) {
		// now disable both useFoundEndpoints and useCloudEndpoints
		s.useFoundEndpoints = false
		s.useCloudEndpoints = false

		// "test" won't be added
		assert.Equal(t, []string{"foo", "bar"}, s.Endpoints([]string{"test"}))
	})

	t.Run("cloudEndpoints not added when useCloudEndpoints is false", func(t *testing.T) {
		s.cloudEndpoints = []string{"new"}

		// "new" is not added because useCloudEndpoints is false
		assert.Equal(t, []string{"foo", "bar"}, s.Endpoints(nil))
	})
}

func TestEndpointSetterOrder(t *testing.T) {
	var e EndpointSetter
	assert.NoError(t, e.SetConfiguredEndpoints("configured"))
	e.SetCloudEndpoints("cloud1", "cloud2")
	e.UseCloudEndpoints(true)
	e.UseFoundEndpoints(true)

	// Configured, then cloud (in the order given), then found - always, regardless
	// of call order above, since found endpoints come from scanned content and
	// must never be tried ahead of operator-controlled sources.
	assert.Equal(t, []string{"configured", "cloud1", "cloud2", "found"}, e.Endpoints([]string{"found"}))
}

func TestEndpointSetterFoundEndpointSuffixFilter(t *testing.T) {
	var e EndpointSetter
	e.UseFoundEndpoints(true)

	// allowedFoundSuffixes is passed at the call site, per call - no stored state.
	got := e.Endpoints(
		[]string{"https://myteam.jira.com", "https://evil.com", "https://evil.com/.jira.com", "notreal.jira.com.evil.com"},
		".jira.com",
	)
	assert.Equal(t, []string{"https://myteam.jira.com"}, got)
}

func TestEndpointSetterFoundEndpointSuffixFilterPortStripped(t *testing.T) {
	var e EndpointSetter
	e.UseFoundEndpoints(true)

	// Port must not defeat the suffix match.
	got := e.Endpoints([]string{"https://myteam.jira.com:8443/path"}, ".jira.com")
	assert.Equal(t, []string{"https://myteam.jira.com:8443/path"}, got)
}

func TestEndpointSetterFoundEndpointSuffixFilterSchemeless(t *testing.T) {
	var e EndpointSetter
	e.UseFoundEndpoints(true)

	got := e.Endpoints(
		[]string{
			"myteam.jira.com",           // bare host, no scheme - allowed
			"evil.com/.jira.com",        // no scheme; url.Parse gives empty Host - must not fall back to raw-string match
			"notreal.jira.com.evil.com", // host really is evil.com, not jira.com
		},
		".jira.com",
	)
	assert.Equal(t, []string{"myteam.jira.com"}, got)
}

func TestEndpointSetterFoundEndpointSuffixFilterUnset(t *testing.T) {
	var e EndpointSetter
	e.UseFoundEndpoints(true)

	// No suffixes passed: nothing is filtered.
	got := e.Endpoints([]string{"https://anything.example.com"})
	assert.Equal(t, []string{"https://anything.example.com"}, got)
}

func TestEndpointSetterCloudEndpointsDeduped(t *testing.T) {
	var e EndpointSetter
	e.SetCloudEndpoints("https://a.com", "https://a.com", "", "https://b.com")
	e.UseCloudEndpoints(true)

	assert.Equal(t, []string{"https://a.com", "https://b.com"}, e.Endpoints(nil))
}

func TestEndpointSetterDedupesAcrossSources(t *testing.T) {
	var e EndpointSetter
	assert.NoError(t, e.SetConfiguredEndpoints("shared.example.com", "configured-only.example.com"))
	e.SetCloudEndpoints("shared.example.com", "cloud-only.example.com")
	e.UseCloudEndpoints(true)
	e.UseFoundEndpoints(true)

	// "shared.example.com" appears as both configured and found, and also as
	// cloud - must appear exactly once in the result, at its highest-priority
	// position (configured), not once per source.
	got := e.Endpoints([]string{"shared.example.com", "found-only.example.com"})
	assert.Equal(t, []string{
		"shared.example.com",
		"configured-only.example.com",
		"cloud-only.example.com",
		"found-only.example.com",
	}, got)
}
