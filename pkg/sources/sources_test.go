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

func TestProgress_SetProgressPercentKeepsResumeInfo(t *testing.T) {
	t.Parallel()
	var p Progress
	p.SetEncodedResumeInfoFor("unit", "key")
	resumeInfo := p.EncodedResumeInfo

	p.SetProgressPercent(42, 10, 20, "scanning")

	got := p.GetProgress()
	assert.Equal(t, int64(42), got.PercentComplete)
	assert.Equal(t, int32(10), got.SectionsCompleted)
	assert.Equal(t, int32(20), got.SectionsRemaining)
	assert.Equal(t, "scanning", got.Message)
	assert.Equal(t, resumeInfo, got.EncodedResumeInfo)
	assert.Equal(t, "key", p.GetEncodedResumeInfoFor("unit"))
}
