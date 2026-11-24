package sources

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// eagerProgress holds the resume-info methods of Progress as they were when
// every per-ID write re-encoded EncodedResumeInfo. It is the reference that
// Progress must match through its supported read paths: GetProgress,
// JobProgress.Snapshot and GetEncodedResumeInfoFor.
type eagerProgress struct {
	mut                   sync.Mutex
	encodedResumeInfoByID map[string]string
	PercentComplete       int64
	Message               string
	EncodedResumeInfo     string
	SectionsCompleted     int32
	SectionsRemaining     int32
}

func (p *eagerProgress) SetProgressComplete(i, scope int, message, encodedResumeInfo string) {
	p.mut.Lock()
	defer p.mut.Unlock()

	p.Message = message
	p.EncodedResumeInfo = encodedResumeInfo
	p.SectionsCompleted = int32(i)
	p.SectionsRemaining = int32(scope)

	// If the iteration and scope are both 0, completion is 100%.
	if i == 0 && scope == 0 {
		p.PercentComplete = 100
		return
	}

	p.PercentComplete = int64((float64(i) / float64(scope)) * 100)
}

func (p *eagerProgress) SetProgressOngoing(message string, encodedResumeInfo string) {
	p.mut.Lock()
	defer p.mut.Unlock()

	p.Message = message
	p.EncodedResumeInfo = encodedResumeInfo
	// Explicitly set SectionsRemaining to 0 so the frontend does not display a percent.
	p.SectionsRemaining = 0
}

func (p *eagerProgress) GetProgress() *eagerProgress {
	p.mut.Lock()
	defer p.mut.Unlock()
	return p
}

func (p *eagerProgress) GetEncodedResumeInfoFor(id string) string {
	p.mut.Lock()
	defer p.mut.Unlock()
	p.ensureEncodedResumeInfoByID()
	return p.encodedResumeInfoByID[id]
}

func (p *eagerProgress) SetEncodedResumeInfoFor(id, value string) {
	p.mut.Lock()
	defer p.mut.Unlock()
	p.ensureEncodedResumeInfoByID()
	p.encodedResumeInfoByID[id] = value
	p.EncodedResumeInfo = marshalEncodedResumeInfo(p.encodedResumeInfoByID)
}

func (p *eagerProgress) ClearEncodedResumeInfoFor(id string) {
	p.mut.Lock()
	defer p.mut.Unlock()
	p.ensureEncodedResumeInfoByID()
	delete(p.encodedResumeInfoByID, id)
	p.EncodedResumeInfo = marshalEncodedResumeInfo(p.encodedResumeInfoByID)
}

func (p *eagerProgress) ensureEncodedResumeInfoByID() {
	if p.encodedResumeInfoByID != nil {
		return
	}
	p.encodedResumeInfoByID = unmarshalEncodedResumeInfo(p.EncodedResumeInfo)
}

// restoredResumeInfo covers the strings a source can be resumed from: none,
// canonical per-ID JSON, JSON with different spacing than json.Marshal
// writes, whole-string formats that are not per-ID JSON, and invalid JSON.
var restoredResumeInfo = []string{
	"",
	`{"u0":"restored-0","u1":"restored-1"}`,
	`{ "u1" : "spaced", "u3":"x" }`,
	`{"current_bucket":"b","start_after":"k"}`,
	`[]`,
	`not json`,
}

// TestProgress_MatchesEagerEncoding runs random sequences of every resume-info
// operation that sources and callers perform through Progress methods, on a
// Progress and on eagerProgress, and checks every supported read agrees. The
// operations include the patterns callers use with the exported field through
// GetProgress: restoring it (p.GetProgress().EncodedResumeInfo = x) and
// writing it back (SetProgressComplete(..., p.GetProgress().EncodedResumeInfo)).
func TestProgress_MatchesEagerEncoding(t *testing.T) {
	t.Parallel()
	for ri, restored := range restoredResumeInfo {
		for _, viaLiteral := range []bool{false, true} {
			t.Run(fmt.Sprintf("restored=%d/literal=%t", ri, viaLiteral), func(t *testing.T) {
				t.Parallel()
				rng := rand.New(rand.NewPCG(uint64(ri), 7))
				for seq := range 1500 {
					runEagerEquivalenceSequence(t, rng, seq, restored, viaLiteral)
				}
			})
		}
	}
}

func runEagerEquivalenceSequence(t *testing.T, rng *rand.Rand, seq int, restored string, viaLiteral bool) {
	t.Helper()
	var p *Progress
	ref := &eagerProgress{}
	if viaLiteral {
		p = &Progress{EncodedResumeInfo: restored}
		ref.EncodedResumeInfo = restored
	} else {
		p = &Progress{}
		p.GetProgress().EncodedResumeInfo = restored
		ref.GetProgress().EncodedResumeInfo = restored
	}
	jp := NewJobProgress(1, 1, "test")
	jp.TrackProgress(p)

	check := func(op int, id string) {
		snap := jp.Snapshot()
		msg := fmt.Sprintf("sequence %d op %d", seq, op)
		require.Equal(t, ref.GetProgress().EncodedResumeInfo, snap.SourceEncodedResumeInfo, "%s: Snapshot resume info", msg)
		require.Equal(t, ref.PercentComplete, snap.SourcePercent, "%s: Snapshot percent", msg)
		require.Equal(t, ref.Message, snap.SourceMessage, "%s: Snapshot message", msg)
		require.Equal(t, ref.SectionsCompleted, snap.SourceSectionsCompleted, "%s: Snapshot sections completed", msg)
		require.Equal(t, ref.SectionsRemaining, snap.SourceSectionsRemaining, "%s: Snapshot sections remaining", msg)
		require.Equal(t, ref.GetProgress().EncodedResumeInfo, p.GetProgress().EncodedResumeInfo, "%s: GetProgress", msg)
		require.Equal(t, ref.GetEncodedResumeInfoFor(id), p.GetEncodedResumeInfoFor(id), "%s: GetEncodedResumeInfoFor(%q)", msg, id)
	}

	for op := range 40 {
		id := fmt.Sprintf("u%d", rng.IntN(5))
		switch rng.IntN(10) {
		case 0, 1, 2:
			value := fmt.Sprintf("v%d", rng.IntN(100))
			p.SetEncodedResumeInfoFor(id, value)
			ref.SetEncodedResumeInfoFor(id, value)
		case 3:
			p.ClearEncodedResumeInfoFor(id)
			ref.ClearEncodedResumeInfoFor(id)
		case 4:
			i, scope := rng.IntN(3), rng.IntN(3)
			whole := restoredResumeInfo[rng.IntN(len(restoredResumeInfo))]
			p.SetProgressComplete(i, scope, "complete", whole)
			ref.SetProgressComplete(i, scope, "complete", whole)
		case 5:
			whole := restoredResumeInfo[rng.IntN(len(restoredResumeInfo))]
			p.SetProgressOngoing("ongoing", whole)
			ref.SetProgressOngoing("ongoing", whole)
		case 6:
			// Write the current value back, as the filesystem source does
			// before scanning each root path.
			p.SetProgressComplete(1, 3, "write back", p.GetProgress().EncodedResumeInfo)
			ref.SetProgressComplete(1, 3, "write back", ref.GetProgress().EncodedResumeInfo)
		case 7:
			// Restore through GetProgress, as a scanner does before a job runs.
			whole := restoredResumeInfo[rng.IntN(len(restoredResumeInfo))]
			p.GetProgress().EncodedResumeInfo = whole
			ref.GetProgress().EncodedResumeInfo = whole
		default:
			check(op, id)
		}
	}
	check(-1, "u0")
}
