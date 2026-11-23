package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestJobProgressFatalErrors(t *testing.T) {
	var jp JobProgress

	// Add a non-fatal error.
	jp.ReportError(fmt.Errorf("oh no"))
	assert.Greater(t, len(jp.Snapshot().Errors), 0)
	assert.NoError(t, jp.Snapshot().FatalError())
	assert.NoError(t, jp.Snapshot().ChunkError())

	// Add a fatal error and make sure we can test comparison.
	err := fmt.Errorf("fatal error")
	jp.ReportError(Fatal{err})
	assert.Greater(t, len(jp.Snapshot().Errors), 0)
	assert.Error(t, jp.Snapshot().FatalError())
	assert.NoError(t, jp.Snapshot().ChunkError())
	assert.True(t, errors.Is(jp.Snapshot().FatalError(), err))

	// Add another fatal error and test we still return the first.
	jp.ReportError(Fatal{fmt.Errorf("second fatal error")})
	assert.Greater(t, len(jp.Snapshot().Errors), 0)
	assert.Error(t, jp.Snapshot().FatalError())
	assert.NoError(t, jp.Snapshot().ChunkError())
	assert.True(t, errors.Is(jp.Snapshot().FatalError(), err))
}

func TestJobProgressRef(t *testing.T) {
	jp := NewJobProgress(123, 456, "source name")
	ref := jp.Ref()
	assert.Equal(t, JobID(123), ref.JobID)
	assert.Equal(t, SourceID(456), ref.SourceID)

	// Test Done() blocks until Finish() is called.
	select {
	case <-jp.Done():
		assert.FailNow(t, "job should not be finished")
	default:
	}

	jp.Finish()
	select {
	case <-jp.Done():
	default:
		assert.FailNow(t, "job should be finished")
	}
}

func TestJobProgressHook(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	hook := NewMockJobProgressHook(ctrl)
	jp := NewJobProgress(123, 456, "source name", WithHooks(hook))

	// Start(JobProgressRef, time.Time)
	// End(JobProgressRef, time.Time)
	// StartEnumerating(JobProgressRef, time.Time)
	// EndEnumerating(JobProgressRef, time.Time)
	// StartUnitChunking(JobProgressRef, SourceUnit, time.Time)
	// EndUnitChunking(JobProgressRef, SourceUnit, time.Time)
	// ReportError(JobProgressRef, error)
	// ReportUnit(JobProgressRef, SourceUnit)
	// ReportChunk(JobProgressRef, SourceUnit, *Chunk)
	// Finish(JobProgressRef)

	startTime := time.Now()
	endTime := time.Now().Add(10 * time.Second)
	startEnum := time.Now().Add(20 * time.Second)
	endEnum := time.Now().Add(30 * time.Second)
	startChunk := time.Now().Add(40 * time.Second)
	endChunk := time.Now().Add(50 * time.Second)
	reportErr := fmt.Errorf("reporting error")
	reportUnit := CommonSourceUnit{ID: "reporting unit"}
	reportChunk := &Chunk{Data: []byte("reporting chunk")}

	hook.EXPECT().Start(gomock.Any(), startTime)
	hook.EXPECT().End(gomock.Any(), endTime)
	hook.EXPECT().StartEnumerating(gomock.Any(), startEnum)
	hook.EXPECT().EndEnumerating(gomock.Any(), endEnum)
	hook.EXPECT().StartUnitChunking(gomock.Any(), reportUnit, startChunk)
	hook.EXPECT().EndUnitChunking(gomock.Any(), reportUnit, endChunk)
	hook.EXPECT().ReportError(gomock.Any(), reportErr)
	hook.EXPECT().ReportUnit(gomock.Any(), reportUnit)
	hook.EXPECT().ReportChunk(gomock.Any(), reportUnit, reportChunk)
	hook.EXPECT().Finish(gomock.Any())

	jp.Start(startTime)
	jp.End(endTime)
	jp.StartEnumerating(startEnum)
	jp.EndEnumerating(endEnum)
	jp.StartUnitChunking(reportUnit, startChunk)
	jp.EndUnitChunking(reportUnit, endChunk)
	jp.ReportError(reportErr)
	jp.ReportUnit(reportUnit)
	jp.ReportChunk(reportUnit, reportChunk)
	jp.Finish()
}

func TestJobProgressErr(t *testing.T) {
	t.Run("ref with no job", func(t *testing.T) {
		ref := JobProgressRef{}
		assert.ErrorIs(t, ref.Err(), ErrNoJob)
		assert.NotErrorIs(t, ref.Err(), ErrJobDone)
	})

	// function to create a cancellable job
	newCancellableJob := func() (context.Context, *JobProgress, JobProgressRef) {
		runCtx, cancel := context.WithCancelCause(context.Background())
		jp := NewJobProgress(123, 456, "source name", WithCancel(cancel))
		return runCtx, jp, jp.Ref()
	}
	t.Run("finished without cancel", func(t *testing.T) {
		_, jp, ref := newCancellableJob()
		// Still running: Err is nil on both the job and the ref.
		assert.NoError(t, jp.Err())
		assert.NoError(t, ref.Err())
		jp.Finish()
		<-ref.Done()
		assert.ErrorIs(t, jp.Err(), ErrJobDone)
		assert.ErrorIs(t, ref.Err(), ErrJobDone)
	})
	t.Run("cancelled via CancelRun", func(t *testing.T) {
		_, jp, ref := newCancellableJob()
		cause := fmt.Errorf("abort! abort!")
		ref.CancelRun(cause)
		// CancelRun only requests a stop. Until Finish runs, Done is still
		// open and Err must still report the job as running.
		select {
		case <-ref.Done():
			assert.FailNow(t, "job should not be done before Finish")
		default:
		}
		assert.NoError(t, jp.Err())
		assert.NoError(t, ref.Err())
		jp.Finish()
		<-ref.Done()
		assert.ErrorIs(t, jp.Err(), cause)
		assert.ErrorIs(t, ref.Err(), cause)
	})
	t.Run("cancel after finish does not change Err", func(t *testing.T) {
		_, jp, ref := newCancellableJob()
		jp.Finish()
		ref.CancelRun(fmt.Errorf("too late"))
		assert.ErrorIs(t, ref.Err(), ErrJobDone)
	})

	t.Run("nil cause is reported as cancelled", func(t *testing.T) {
		_, jp, ref := newCancellableJob()
		ref.CancelRun(nil)
		jp.Finish()
		assert.ErrorIs(t, ref.Err(), context.Canceled)
		assert.NotErrorIs(t, ref.Err(), ErrJobDone)
	})

	t.Run("first cause wins", func(t *testing.T) {
		runCtx, jp, ref := newCancellableJob()
		first := fmt.Errorf("first cause")
		second := fmt.Errorf("second cause")
		ref.CancelRun(first)
		ref.CancelRun(second)
		// The source's run context sees the first cause, not the second.
		assert.ErrorIs(t, context.Cause(runCtx), first)
		jp.Finish()
		<-ref.Done()
		assert.ErrorIs(t, ref.Err(), first)
		assert.NotErrorIs(t, ref.Err(), second)
	})
}

func TestJobProgressDone(t *testing.T) {
	ref := JobProgressRef{}
	select {
	case <-ref.Done():
	default:
		assert.FailNow(t, "done should not block for a nil job")
	}
}

func TestJobProgressElapsedTime(t *testing.T) {
	metrics := JobProgressMetrics{}
	assert.Equal(t, time.Duration(0), metrics.ElapsedTime())

	startTime := time.Date(2022, time.March, 30, 0, 0, 0, 0, time.UTC)
	metrics.StartTime = &startTime
	assert.Greater(t, metrics.ElapsedTime(), time.Duration(0))

	endTime := metrics.StartTime.Add(1 * time.Hour)
	metrics.EndTime = &endTime
	assert.Equal(t, metrics.ElapsedTime(), 1*time.Hour)
}

func TestJobProgressErrorsFor(t *testing.T) {
	metrics := JobProgressMetrics{
		Errors: []error{
			Fatal{ChunkError{
				Unit: CommonSourceUnit{ID: "foo"},
				Err:  fmt.Errorf("foo error"),
			}},
			ChunkError{
				Unit: CommonSourceUnit{ID: "foo"},
				Err:  fmt.Errorf("foo again error"),
			},
			ChunkError{
				Unit: CommonSourceUnit{ID: "bar"},
				Err:  fmt.Errorf("bar error"),
			},
			fmt.Errorf("hi there"),
		},
	}
	assert.Equal(t, 2, len(metrics.ErrorsFor(CommonSourceUnit{ID: "foo"})))
	assert.Equal(t, 1, len(metrics.ErrorsFor(CommonSourceUnit{ID: "bar"})))
	assert.Equal(t, 0, len(metrics.ErrorsFor(CommonSourceUnit{ID: "baz"})))
}

func TestJobProgressRefUnitProgress(t *testing.T) {
	var progress Progress
	jp := NewJobProgress(123, 456, "source name")
	jp.TrackProgress(&progress)
	ref := jp.Ref()

	_, ok := ref.UnitProgress("unit")
	assert.False(t, ok)

	want := UnitProgress{State: UnitProgressCounting, ItemsDone: 3, BytesDone: 300}
	progress.SetUnitProgressFor("unit", want)
	got, ok := ref.UnitProgress("unit")
	assert.True(t, ok)
	assert.Equal(t, want, got)

	// A ref to no job, or to a job whose source reports no progress, has none to give.
	_, ok = (&JobProgressRef{}).UnitProgress("unit")
	assert.False(t, ok)
	untracked := NewJobProgress(123, 456, "source name").Ref()
	_, ok = untracked.UnitProgress("unit")
	assert.False(t, ok)
}

// TestJobProgress_SnapshotEdgeCases is not parallel because its allocation
// check counts allocations made by every goroutine in the process.
func TestJobProgress_SnapshotEdgeCases(t *testing.T) {
	t.Run("nil tracked progress returns zero source fields", func(t *testing.T) {
		t.Parallel()
		jp := NewJobProgress(1, 1, "untracked")
		snap := jp.Snapshot()
		assert.Empty(t, snap.SourceEncodedResumeInfo)
		assert.Empty(t, snap.SourceMessage)
		assert.Zero(t, snap.SourcePercent)
		assert.Zero(t, snap.SourceSectionsCompleted)
		assert.Zero(t, snap.SourceSectionsRemaining)

		jp.TrackProgress(nil)
		snap = jp.Snapshot()
		assert.Empty(t, snap.SourceEncodedResumeInfo)
	})

	t.Run("repeated snapshots without intervening writes do not re-encode", func(t *testing.T) {
		var p Progress
		jp := NewJobProgress(1, 1, "clean-snapshot")
		jp.TrackProgress(&p)

		for i := range 200 {
			p.SetEncodedResumeInfoFor(fmt.Sprintf("unit-%03d", i), "checkpoint")
		}
		first := jp.Snapshot().SourceEncodedResumeInfo
		require.NotEmpty(t, first)

		// Encoding 200 entries allocates hundreds of times, so reads that
		// reuse the last encode allocate nothing.
		allocs := testing.AllocsPerRun(100, func() {
			jp.Snapshot()
			p.GetProgress()
		})
		assert.Zero(t, allocs)
		assert.Equal(t, first, jp.Snapshot().SourceEncodedResumeInfo)
		assert.Equal(t, first, p.GetProgress().EncodedResumeInfo)

		p.SetEncodedResumeInfoFor("unit-000", "next")
		assert.NotEqual(t, first, jp.Snapshot().SourceEncodedResumeInfo)
	})

	t.Run("concurrent resume info, unit progress, whole-string progress, errors, chunks, and snapshots", func(t *testing.T) {
		t.Parallel()
		const workers, iters = 6, 500
		var p Progress
		jp := NewJobProgress(1, 1, "stress")
		jp.TrackProgress(&p)

		var wg sync.WaitGroup
		for w := range workers {
			wg.Add(1)
			go func(worker int) {
				defer wg.Done()
				id := fmt.Sprintf("u%d", worker)
				for i := range iters {
					if i%11 == 0 {
						p.ClearEncodedResumeInfoFor(id)
					}
					p.SetEncodedResumeInfoFor(id, strconv.Itoa(i))
					_ = p.GetEncodedResumeInfoFor(id)
					p.SetUnitProgressFor(id, UnitProgress{
						State:      UnitProgressReady,
						ItemsDone:  uint64(i),
						ItemsTotal: uint64(iters),
					})
					_, _ = jp.UnitProgress(id)
					jp.ReportChunk(nil, &Chunk{})
					if i%50 == 0 {
						jp.ReportError(errors.New("transient"))
					}
				}
			}(w)
		}

		// Interleave whole-string writes and Snapshot reads concurrently.
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := range iters {
				if i%2 == 0 {
					p.SetProgressComplete(i, iters, "progress", "")
				} else {
					p.SetProgressOngoing("ongoing", "")
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range iters {
				snap := jp.Snapshot()
				if snap.SourceEncodedResumeInfo != "" {
					var m map[string]string
					assert.NoError(t, json.Unmarshal([]byte(snap.SourceEncodedResumeInfo), &m))
				}
				p.GetProgress()
			}
		}()
		wg.Wait()

		// Final per-unit write after concurrent activity must encode all worker keys.
		p.SetEncodedResumeInfoFor("final", "done")
		var got map[string]string
		require.NoError(t, json.Unmarshal([]byte(jp.Snapshot().SourceEncodedResumeInfo), &got))
		assert.Equal(t, "done", got["final"])
		for w := range workers {
			assert.Equal(t, strconv.Itoa(iters-1), got[fmt.Sprintf("u%d", w)])
		}
	})
}

// A monitor snapshots a job while its source saves resume info. Each save here
// moves one unit's position forward, so every reader must see positions that
// never move backward, and a snapshot taken after the last save must hold it.
func TestJobProgress_SnapshotsSeeResumeInfoMoveForward(t *testing.T) {
	t.Parallel()
	const saves, readers = 5000, 4
	var p Progress
	jp := NewJobProgress(1, 1, "test")
	jp.TrackProgress(&p)

	position := func(encoded string) int {
		if encoded == "" {
			return -1
		}
		byID := unmarshalEncodedResumeInfo(encoded)
		n, err := strconv.Atoi(byID["unit"])
		if !assert.NoError(t, err, "resume info %q", encoded) {
			return -1
		}
		return n
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	for r := range readers {
		wg.Go(func() {
			last := -1
			for {
				var got int
				if r%2 == 0 {
					got = position(jp.Snapshot().SourceEncodedResumeInfo)
				} else {
					// GetProgress shares the encoded string with
					// Snapshot, so both kinds of reader run together.
					p.GetProgress()
					got = position(jp.Snapshot().SourceEncodedResumeInfo)
				}
				if got < last {
					t.Errorf("reader %d saw position %d after %d", r, got, last)
					return
				}
				last = got
				select {
				case <-done:
					return
				default:
				}
			}
		})
	}

	for i := range saves {
		p.SetEncodedResumeInfoFor("unit", strconv.Itoa(i))
		jp.ReportChunk(nil, &Chunk{})
	}
	close(done)
	wg.Wait()

	assert.Equal(t, saves-1, position(jp.Snapshot().SourceEncodedResumeInfo))
	assert.Equal(t, saves-1, position(p.GetProgress().EncodedResumeInfo))
}

// A source reports a chunk and then saves the position after it. A snapshot
// must not hold a position past the chunks it counted, so that resume info
// never claims more work than the snapshot's own counters show.
func TestSnapshot_ResumeInfoNotAheadOfChunkCount(t *testing.T) {
	const chunks = 20000
	var p Progress
	jp := NewJobProgress(1, 1, "test")
	jp.TrackProgress(&p)

	done := make(chan struct{})
	var wg sync.WaitGroup
	var ahead, snapshots int
	wg.Go(func() {
		for {
			snapshot := jp.Snapshot()
			snapshots++
			if encoded := snapshot.SourceEncodedResumeInfo; encoded != "" {
				position, _ := strconv.Atoi(unmarshalEncodedResumeInfo(encoded)["unit"])
				if uint64(position) > snapshot.TotalChunks {
					ahead++
				}
			}
			select {
			case <-done:
				return
			default:
			}
		}
	})

	for i := 1; i <= chunks; i++ {
		jp.ReportChunk(nil, &Chunk{})
		p.SetEncodedResumeInfoFor("unit", strconv.Itoa(i))
	}
	close(done)
	wg.Wait()

	assert.Zero(t, ahead, "of %d snapshots, %d held resume info past their chunk count", snapshots, ahead)
}
