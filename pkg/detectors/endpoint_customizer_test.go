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
