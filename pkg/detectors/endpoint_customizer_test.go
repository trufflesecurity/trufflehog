package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmbeddedEndpointSetter(t *testing.T) {
	type Scanner struct{ EndpointSetter }
	var s Scanner
	// set useFoundEndpoints to true to add the "baz" in endpoints
	s.useFoundEndpoints = true
	assert.Equal(t, []string{"baz"}, s.Endpoints("baz"))
	// setting "foo" and "bar" as configured endpoint
	assert.NoError(t, s.SetConfiguredEndpoints("foo", "bar"))
	// return error as no endpoints are passed
	assert.Error(t, s.SetConfiguredEndpoints())
	// as useFoundEndpoints is true, "baz" will be added in the endpoints list
	assert.Equal(t, []string{"foo", "bar", "baz"}, s.Endpoints("baz"))
	// setting cloudEndpoint along with setting useCloudEndpoint as true
	s.useCloudEndpoint = true
	// cloudEndpoint must be set in order to be added in the list along with useCloudEndpoint as true
	s.cloudEndpoint = "test"
	// reason for "foo" and "bar" here is that they are already configured
	assert.Equal(t, []string{"foo", "bar", "test"}, s.Endpoints())
	// set useFoundEndpoints and useCloudEndpoint to false
	s.useFoundEndpoints = false
	s.useCloudEndpoint = false
	// as both useFoundEndpoints and useCloudEndpoint are set to false, passing any endpoint to Endpoints() will not be added
	assert.Equal(t, []string{"foo", "bar"}, s.Endpoints("test"))
	// set any new endpoint as cloudEndpoint
	s.cloudEndpoint = "new"
	// this time it will not be added in list because useCloudEndpoint is set to false
	assert.Equal(t, []string{"foo", "bar"}, s.Endpoints())
}
