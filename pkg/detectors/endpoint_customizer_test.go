package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmbeddedEndpointSetter(t *testing.T) {
	type Scanner struct{ EndpointSetter }
	var s Scanner
	// use foundendpoint to set the "baz" in endpoints
	s.useFoundEndpoints = true
	assert.Equal(t, []string{"baz"}, s.Endpoints("baz"))
	// setting "foo" and "bar" as configured endpoint
	assert.NoError(t, s.SetConfiguredEndpoints("foo", "bar"))
	// return error as no endpoints are passed
	assert.Error(t, s.SetConfiguredEndpoints())
	// as use foundendpoint is true, "baz" will be added in the endpoints list
	assert.Equal(t, []string{"foo", "bar", "baz"}, s.Endpoints("baz"))
	// setting cloudendpoints
	s.useCloudEndpoint = true
	// cloudendpoint must be set in order to be added in the list along with useCloudEndpoint as true
	s.cloudEndpoint = "test"
	// reason for "foo" and "bar" here is that they are already configured
	assert.Equal(t, []string{"foo", "bar", "test"}, s.Endpoints())
}
