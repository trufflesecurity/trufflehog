package sources

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

// TestChunkSize ensures that the Chunk struct does not exceed 80 bytes.
func TestChunkSize(t *testing.T) {
	t.Parallel()
	assert.Equal(t, unsafe.Sizeof(Chunk{}), uintptr(80), "Chunk struct size exceeds 80 bytes")
}
