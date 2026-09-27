package sources

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
