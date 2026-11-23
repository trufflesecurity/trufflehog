package sources

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strconv"
	"sync"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// resumeInfoModel is a reference for how Progress resume info behaves: per-ID
// writes update a map decoded from the encoded string on first use and then
// re-encode it, and whole-string writes replace the string but not the map.
type resumeInfoModel struct {
	encoded string
	byID    map[string]string
}

func (m *resumeInfoModel) ensureByID() {
	if m.byID == nil {
		m.byID = map[string]string{}
		_ = json.Unmarshal([]byte(m.encoded), &m.byID)
	}
}

func (m *resumeInfoModel) set(id, value string) {
	m.ensureByID()
	m.byID[id] = value
	m.encode()
}

func (m *resumeInfoModel) clear(id string) {
	m.ensureByID()
	delete(m.byID, id)
	m.encode()
}

func (m *resumeInfoModel) encode() {
	encoded, _ := json.Marshal(m.byID)
	m.encoded = string(encoded)
}

func (m *resumeInfoModel) get(id string) string {
	m.ensureByID()
	return m.byID[id]
}

func TestProgress_ResumeInfoMatchesModel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		wholeWrites bool
	}{
		{name: "per-ID writes", wholeWrites: false},
		{name: "per-ID and whole-string writes", wholeWrites: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rng := rand.New(rand.NewPCG(1, 2))
			for seq := range 2000 {
				var p Progress
				var model resumeInfoModel
				jp := NewJobProgress(1, 1, "test")
				jp.TrackProgress(&p)
				// Half the sequences resume from encoded info restored before any per-ID write.
				if seq%2 == 0 {
					restored := `{"u0":"restored-0","u1":"restored-1"}`
					p.GetProgress().EncodedResumeInfo = restored
					model.encoded = restored
				}

				for op := range 30 {
					id := fmt.Sprintf("u%d", rng.IntN(4))
					switch k := rng.IntN(7); {
					case k <= 1:
						value := fmt.Sprintf("v%d", rng.IntN(100))
						p.SetEncodedResumeInfoFor(id, value)
						model.set(id, value)
					case k == 2:
						p.ClearEncodedResumeInfoFor(id)
						model.clear(id)
					case k == 3 && tt.wholeWrites:
						whole := fmt.Sprintf(`{"u%d":"whole-%d"}`, rng.IntN(4), rng.IntN(100))
						p.SetProgressComplete(1, 2, "message", whole)
						model.encoded = whole
					case k == 4 && tt.wholeWrites:
						whole := fmt.Sprintf(`{"u%d":"whole-%d"}`, rng.IntN(4), rng.IntN(100))
						p.SetProgressOngoing("message", whole)
						model.encoded = whole
					default:
						require.Equal(t, model.encoded, jp.Snapshot().SourceEncodedResumeInfo, "sequence %d op %d: Snapshot", seq, op)
						require.Equal(t, model.encoded, p.GetProgress().EncodedResumeInfo, "sequence %d op %d: GetProgress", seq, op)
						require.Equal(t, model.get(id), p.GetEncodedResumeInfoFor(id), "sequence %d op %d: GetEncodedResumeInfoFor(%q)", seq, op, id)
					}
				}
			}
		})
	}
}

func TestProgress_ConcurrentResumeInfoWritesAndReads(t *testing.T) {
	t.Parallel()
	const writers, writes = 8, 2000
	var p Progress
	jp := NewJobProgress(1, 1, "test")
	jp.TrackProgress(&p)

	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			id := fmt.Sprintf("u%d", w)
			for i := range writes {
				if i%7 == 0 {
					p.ClearEncodedResumeInfoFor(id)
				}
				p.SetEncodedResumeInfoFor(id, strconv.Itoa(i))
				jp.ReportChunk(nil, &Chunk{})
			}
		})
	}
	for range 2 {
		wg.Go(func() {
			for range writes {
				if encoded := jp.Snapshot().SourceEncodedResumeInfo; encoded != "" {
					var resumeInfo map[string]string
					assert.NoError(t, json.Unmarshal([]byte(encoded), &resumeInfo))
				}
				p.GetProgress()
			}
		})
	}
	wg.Wait()

	want := make(map[string]string, writers)
	for w := range writers {
		want[fmt.Sprintf("u%d", w)] = strconv.Itoa(writes - 1)
	}
	var got map[string]string
	require.NoError(t, json.Unmarshal([]byte(jp.Snapshot().SourceEncodedResumeInfo), &got))
	assert.Equal(t, want, got)
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
