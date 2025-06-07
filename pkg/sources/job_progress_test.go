package sources

import (
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
