package sources

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

// TestChunkSize ensures that the Chunk struct does not exceed 104 bytes.
// Size increased from 80 to 104 with the addition of OriginalData []byte
// (24-byte slice header) for secret storage chunk threading.
func TestChunkSize(t *testing.T) {
	t.Parallel()
	assert.Equal(t, unsafe.Sizeof(Chunk{}), uintptr(104), "Chunk struct size exceeds 104 bytes")
}
