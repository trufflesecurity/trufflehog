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

func TestProgress_UnitProgressKeepsResumeInfo(t *testing.T) {
	t.Parallel()
	var p Progress
	p.SetEncodedResumeInfoFor("unit", "key")
	resumeInfo := p.EncodedResumeInfo

	want := UnitProgress{State: UnitProgressReady, ItemsDone: 1, ItemsTotal: 2, BytesDone: 10, BytesTotal: 20}
	p.SetUnitProgressFor("unit", want)

	got, ok := p.GetUnitProgressFor("unit")
	assert.True(t, ok)
	assert.Equal(t, want, got)
	assert.Equal(t, resumeInfo, p.EncodedResumeInfo)
	assert.Equal(t, "key", p.GetEncodedResumeInfoFor("unit"))

	_, ok = p.GetUnitProgressFor("other unit")
	assert.False(t, ok)
}

func TestUnitProgress_Percent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		progress UnitProgress
		want     int64
	}{
		{name: "nothing reported", progress: UnitProgress{}, want: 0},
		{
			name:     "still counting",
			progress: UnitProgress{State: UnitProgressCounting, BytesDone: 500, BytesTotal: 1000},
			want:     0,
		},
		{
			name:     "count unavailable",
			progress: UnitProgress{State: UnitProgressUnavailable, BytesDone: 500, BytesTotal: 1000},
			want:     0,
		},
		{name: "empty total", progress: UnitProgress{State: UnitProgressReady}, want: 0},
		{
			name:     "partial rounds down",
			progress: UnitProgress{State: UnitProgressReady, BytesDone: 1999, BytesTotal: 3000},
			want:     66,
		},
		{
			name:     "all done caps at 99",
			progress: UnitProgress{State: UnitProgressReady, BytesDone: 1000, BytesTotal: 1000},
			want:     99,
		},
		{
			name:     "done past total caps at 99",
			progress: UnitProgress{State: UnitProgressReady, BytesDone: 1200, BytesTotal: 1000},
			want:     99,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.progress.Percent())
		})
	}
}
