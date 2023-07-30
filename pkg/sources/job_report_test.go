package sources

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestJobReportFatalErrors(t *testing.T) {
	var jr JobReport

	// Add a non-fatal error.
	jr.ReportError(fmt.Errorf("oh no"))
	assert.Greater(t, len(jr.Snapshot().Errors), 0)
	assert.NoError(t, jr.Snapshot().FatalError())
	assert.NoError(t, jr.Snapshot().ChunkError())

	// Add a fatal error and make sure we can test comparison.
	err := fmt.Errorf("fatal error")
	jr.ReportError(Fatal{err})
	assert.Greater(t, len(jr.Snapshot().Errors), 0)
	assert.Error(t, jr.Snapshot().FatalError())
	assert.NoError(t, jr.Snapshot().ChunkError())
	assert.True(t, errors.Is(jr.Snapshot().FatalError(), err))

	// Add another fatal error and test we still return the first.
	jr.ReportError(Fatal{fmt.Errorf("second fatal error")})
	assert.Greater(t, len(jr.Snapshot().Errors), 0)
	assert.Error(t, jr.Snapshot().FatalError())
	assert.NoError(t, jr.Snapshot().ChunkError())
	assert.True(t, errors.Is(jr.Snapshot().FatalError(), err))
}

func TestJobReportRef(t *testing.T) {
	jr := NewJobReport(123, 456)
	ref := jr.Ref()
	assert.Equal(t, int64(123), ref.SourceID)
	assert.Equal(t, int64(456), ref.JobID)

	// Test Done() blocks until Finish() is called.
	select {
	case <-jr.Done():
		assert.FailNow(t, "job should not be finished")
	default:
	}

	jr.Finish()
	select {
	case <-jr.Done():
	default:
		assert.FailNow(t, "job should be finished")
	}
}

func TestJobReportHook(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	hook := NewMockJobReportHook(ctrl)
	jr := NewJobReport(123, 456, WithHooks(hook))

	// Start(JobReportRef, time.Time)
	// End(JobReportRef, time.Time)
	// StartEnumerating(JobReportRef, time.Time)
	// EndEnumerating(JobReportRef, time.Time)
	// StartUnitChunking(JobReportRef, SourceUnit, time.Time)
	// EndUnitChunking(JobReportRef, SourceUnit, time.Time)
	// ReportError(JobReportRef, error)
	// ReportUnit(JobReportRef, SourceUnit)
	// ReportChunk(JobReportRef, SourceUnit, *Chunk)
	// Finish(JobReportRef)

	startTime := time.Now()
	endTime := time.Now().Add(10 * time.Second)
	startEnum := time.Now().Add(20 * time.Second)
	endEnum := time.Now().Add(30 * time.Second)
	startChunk := time.Now().Add(40 * time.Second)
	endChunk := time.Now().Add(50 * time.Second)
	reportErr := fmt.Errorf("reporting error")
	reportUnit := CommonSourceUnit{"reporting unit"}
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

	jr.Start(startTime)
	jr.End(endTime)
	jr.StartEnumerating(startEnum)
	jr.EndEnumerating(endEnum)
	jr.StartUnitChunking(reportUnit, startChunk)
	jr.EndUnitChunking(reportUnit, endChunk)
	jr.ReportError(reportErr)
	jr.ReportUnit(reportUnit)
	jr.ReportChunk(reportUnit, reportChunk)
	jr.Finish()
}
