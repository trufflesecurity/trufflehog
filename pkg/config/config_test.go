package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewYAML_SourceDebug(t *testing.T) {
	// The second source has no debug field, like every config written before
	// the field existed, so it must stay off.
	input := []byte(`
sources:
- name: with debug
  type: SOURCE_TYPE_FILESYSTEM
  debug: true
  connection:
    '@type': type.googleapis.com/sources.Filesystem
    paths: [.]
- name: without debug
  type: SOURCE_TYPE_FILESYSTEM
  connection:
    '@type': type.googleapis.com/sources.Filesystem
    paths: [.]
`)

	conf, err := NewYAML(input)
	require.NoError(t, err)
	require.Len(t, conf.Sources, 2)

	assert.Equal(t, "with debug", conf.Sources[0].Name)
	assert.True(t, conf.Sources[0].Debug)
	assert.Equal(t, "without debug", conf.Sources[1].Name)
	assert.False(t, conf.Sources[1].Debug)
}
