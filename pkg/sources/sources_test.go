package sources

import (
	"fmt"
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

	want := UnitProgress{State: UnitProgressReady, ItemsDone: 1, ItemsTotal: 2, BytesDone: 10, BytesTotal: 20}
	p.SetUnitProgressFor("unit", want)

	got, ok := p.GetUnitProgressFor("unit")
	assert.True(t, ok)
	assert.Equal(t, want, got)
	assert.Equal(t, `{"unit":"key"}`, p.GetProgress().EncodedResumeInfo)
	assert.Equal(t, "key", p.GetEncodedResumeInfoFor("unit"))

	_, ok = p.GetUnitProgressFor("other unit")
	assert.False(t, ok)
}

func TestProgress_ResumeInfoReadsSeeLatestWrite(t *testing.T) {
	t.Parallel()
	var p Progress
	jp := NewJobProgress(1, 1, "test")
	jp.TrackProgress(&p)

	p.SetEncodedResumeInfoFor("a", "1")
	p.SetEncodedResumeInfoFor("b", "2")
	assert.Equal(t, `{"a":"1","b":"2"}`, p.GetProgress().EncodedResumeInfo)
	assert.Equal(t, `{"a":"1","b":"2"}`, jp.Snapshot().SourceEncodedResumeInfo)

	p.ClearEncodedResumeInfoFor("a")
	assert.Equal(t, `{"b":"2"}`, jp.Snapshot().SourceEncodedResumeInfo)
	assert.Equal(t, `{"b":"2"}`, p.GetProgress().EncodedResumeInfo)

	p.SetEncodedResumeInfoFor("c", "3")
	p.SetProgressComplete(1, 2, "message", "whole")
	assert.Equal(t, "whole", jp.Snapshot().SourceEncodedResumeInfo)
	assert.Equal(t, "whole", p.GetProgress().EncodedResumeInfo)

	p.SetEncodedResumeInfoFor("d", "4")
	p.SetProgressOngoing("message", "ongoing")
	assert.Equal(t, "ongoing", jp.Snapshot().SourceEncodedResumeInfo)
	assert.Equal(t, "ongoing", p.GetProgress().EncodedResumeInfo)
}

// Resume info restored into a Progress must reach its readers unchanged until
// something is saved per ID: the restored string is what the previous run
// persisted, and re-encoding it without a new save could reorder or reformat
// it. Each case restores the same string a different way.
func TestProgress_RestoredResumeInfoIsReadBackVerbatim(t *testing.T) {
	t.Parallel()
	// The spacing and key order differ from what encoding the per-ID map
	// produces, so a re-encode is visible.
	const restored = `{ "b": "2",  "a": "1" }`
	tests := []struct {
		name    string
		restore func() *Progress
	}{
		{name: "struct literal", restore: func() *Progress { return &Progress{EncodedResumeInfo: restored} }},
		{name: "assignment through GetProgress", restore: func() *Progress {
			var p Progress
			p.GetProgress().EncodedResumeInfo = restored
			return &p
		}},
		{name: "assignment to the field", restore: func() *Progress {
			var p Progress
			p.EncodedResumeInfo = restored
			return &p
		}},
		{name: "SetProgressComplete", restore: func() *Progress {
			var p Progress
			p.SetProgressComplete(0, 1, "message", restored)
			return &p
		}},
		{name: "SetProgressOngoing", restore: func() *Progress {
			var p Progress
			p.SetProgressOngoing("message", restored)
			return &p
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.restore()
			jp := NewJobProgress(1, 1, "test")
			jp.TrackProgress(p)

			assert.Equal(t, restored, jp.Snapshot().SourceEncodedResumeInfo)
			assert.Equal(t, restored, p.GetProgress().EncodedResumeInfo)

			// Reading per ID decodes the string but saves nothing.
			assert.Equal(t, "1", p.GetEncodedResumeInfoFor("a"))
			assert.Equal(t, "2", p.GetEncodedResumeInfoFor("b"))
			assert.Empty(t, p.GetEncodedResumeInfoFor("c"))
			assert.Equal(t, restored, jp.Snapshot().SourceEncodedResumeInfo)
			assert.Equal(t, restored, p.GetProgress().EncodedResumeInfo)

			// The first per-ID save re-encodes every restored entry.
			p.SetEncodedResumeInfoFor("c", "3")
			assert.Equal(t, `{"a":"1","b":"2","c":"3"}`, jp.Snapshot().SourceEncodedResumeInfo)
			assert.Equal(t, `{"a":"1","b":"2","c":"3"}`, p.GetProgress().EncodedResumeInfo)
		})
	}
}

// Clearing an ID is a save like any other: the next read must reflect it,
// including when it empties the resume info or names an ID that was never
// saved.
func TestProgress_ClearThenRead(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		restored string
		clear    []string
		want     string
	}{
		{name: "one of two restored entries", restored: `{"a":"1","b":"2"}`, clear: []string{"a"}, want: `{"b":"2"}`},
		{name: "every restored entry", restored: `{"a":"1","b":"2"}`, clear: []string{"a", "b"}, want: `{}`},
		{name: "an ID that was never saved", restored: `{"a":"1"}`, clear: []string{"z"}, want: `{"a":"1"}`},
		{name: "an ID on empty resume info", restored: ``, clear: []string{"a"}, want: `{}`},
		{name: "an ID on resume info that is not a per-ID map", restored: `opaque whole-string info`, clear: []string{"a"}, want: `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Progress
			jp := NewJobProgress(1, 1, "test")
			jp.TrackProgress(&p)
			p.GetProgress().EncodedResumeInfo = tt.restored

			for _, id := range tt.clear {
				p.ClearEncodedResumeInfoFor(id)
			}

			assert.Equal(t, tt.want, jp.Snapshot().SourceEncodedResumeInfo)
			assert.Equal(t, tt.want, p.GetProgress().EncodedResumeInfo)
			for _, id := range tt.clear {
				assert.Empty(t, p.GetEncodedResumeInfoFor(id))
			}
		})
	}
}

// Resume info restored through GetProgress after per-ID saves replaces what
// those saves encoded, and stays in place until the next per-ID save.
func TestProgress_RestoreThroughGetProgressAfterPerIDSave(t *testing.T) {
	t.Parallel()
	var p Progress
	jp := NewJobProgress(1, 1, "test")
	jp.TrackProgress(&p)

	p.SetEncodedResumeInfoFor("a", "1")
	p.GetProgress().EncodedResumeInfo = "restored"
	assert.Equal(t, "restored", jp.Snapshot().SourceEncodedResumeInfo)
	assert.Equal(t, "restored", p.GetProgress().EncodedResumeInfo)

	p.SetEncodedResumeInfoFor("b", "2")
	assert.Equal(t, `{"a":"1","b":"2"}`, jp.Snapshot().SourceEncodedResumeInfo)
	assert.Equal(t, `{"a":"1","b":"2"}`, p.GetProgress().EncodedResumeInfo)
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

// restoredProgress returns a Progress resumed with resume info for the given
// number of units, and the unit IDs it holds.
func restoredProgress(units int) (*Progress, []string) {
	ids := make([]string, units)
	resumeInfo := make(map[string]string, units)
	for i := range ids {
		ids[i] = fmt.Sprintf("unit-%05d", i)
		resumeInfo[ids[i]] = "path/to/last/scanned/object.json"
	}
	p := &Progress{EncodedResumeInfo: marshalEncodedResumeInfo(resumeInfo)}
	p.GetEncodedResumeInfoFor(ids[0])
	return p, ids
}

func BenchmarkProgress_SetEncodedResumeInfoFor(b *testing.B) {
	for _, units := range []int{1_500, 30_000} {
		b.Run(fmt.Sprintf("units=%d", units), func(b *testing.B) {
			p, ids := restoredProgress(units)
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				p.SetEncodedResumeInfoFor(ids[i%units], "path/to/next/scanned/object.json")
				i++
			}
		})
	}
}

func BenchmarkJobProgress_SnapshotAfterSave(b *testing.B) {
	for _, units := range []int{1_500, 30_000} {
		b.Run(fmt.Sprintf("units=%d", units), func(b *testing.B) {
			p, ids := restoredProgress(units)
			jp := NewJobProgress(1, 1, "benchmark")
			jp.TrackProgress(p)
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				p.SetEncodedResumeInfoFor(ids[i%units], "path/to/next/scanned/object.json")
				_ = jp.Snapshot()
				i++
			}
		})
	}
}
