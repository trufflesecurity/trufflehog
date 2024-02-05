package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmbeddedEndpointSetter(t *testing.T) {
	type Scanner struct{ EndpointSetter }
	var s Scanner
	assert.Equal(t, []string{"baz"}, s.Endpoints("baz"))
	assert.NoError(t, s.SetEndpoints("foo", "bar"))
	assert.Error(t, s.SetEndpoints())
	assert.Equal(t, []string{"foo", "bar"}, s.Endpoints("baz"))
}
