package report

import (
	"errors"
	"fmt"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// UnitHook implements JobProgressHook for tracking the progress of each
// individual unit.
type UnitHook struct {
	inProgressMetrics *ProgressTracker[string, UnitMetrics]
	sources.NoopHook
}

type UnitHookOpt func(*UnitHook)

func OnFinishedMetric(f func(metrics UnitMetrics)) UnitHookOpt {
	// Return a function that, when invoked, modifies the existing
	// uh.inProgressMetrics. It may look a bit strange to call it this way,
	// but it works.
	return func(uh *UnitHook) {
		OnRemove(func(_ string, metrics UnitMetrics) {
			f(metrics)
		})(uh.inProgressMetrics)
	}
}

func OnClose(f func()) UnitHookOpt {
	// Return a function that, when invoked, modifies the existing
	// uh.inProgressMetrics. It may look a bit strange to call it this way,
	// but it works.
	return func(uh *UnitHook) {
		OnStop[string, UnitMetrics](f)(uh.inProgressMetrics)
	}
}

func NewUnitHook(opts ...UnitHookOpt) *UnitHook {
	hook := UnitHook{
		inProgressMetrics: NewProgressTracker[string, UnitMetrics](),
	}
	for _, opt := range opts {
		opt(&hook)
	}
	return &hook
}

// id is a helper method to generate an ID for the given job and unit.
func (u *UnitHook) id(ref sources.JobProgressRef, unit sources.SourceUnit) string {
	unitID := ""
	if unit != nil {
		id, kind := unit.SourceUnitID()
		unitID = fmt.Sprintf("%s:%s", kind, id)
	}
	return fmt.Sprintf("%d/%d/%s", ref.SourceID, ref.JobID, unitID)
}

func (u *UnitHook) StartUnitChunking(ref sources.JobProgressRef, unit sources.SourceUnit, start time.Time) {
	id := u.id(ref, unit)
	u.inProgressMetrics.Add(id, UnitMetrics{
		Unit:      unit,
		Parent:    ref,
		StartTime: &start,
	})
}

func (u *UnitHook) EndUnitChunking(ref sources.JobProgressRef, unit sources.SourceUnit, end time.Time) {
	id := u.id(ref, unit)

	u.inProgressMetrics.UpdateAndRemove(id, func(um *UnitMetrics) {
		um.EndTime = &end
	})
}

func (u *UnitHook) ReportChunk(ref sources.JobProgressRef, unit sources.SourceUnit, chunk *sources.Chunk) {
	id := u.id(ref, unit)

	// TODO: Handle non-unit sources?
	u.inProgressMetrics.Update(id, func(um *UnitMetrics) {
		um.TotalChunks++
		um.TotalBytes += uint64(len(chunk.Data))
	})
}

func (u *UnitHook) ReportError(ref sources.JobProgressRef, err error) {
	// TODO: Handle non-unit sources?

	// Check if it's a ChunkError for a specific unit.
	var chunkErr sources.ChunkError
	if !errors.As(err, &chunkErr) {
		return
	}
	id := u.id(ref, chunkErr.Unit)

	u.inProgressMetrics.Update(id, func(um *UnitMetrics) {
		um.Errors = append(um.Errors, err)
	})
}

func (u *UnitHook) Finish(ref sources.JobProgressRef) {
	// TODO: Handle non-unit sources?
}

// InProgressSnapshot gets all the currently active metrics across all jobs.
func (u *UnitHook) InProgressSnapshot() []UnitMetrics {
	return u.inProgressMetrics.InProgressSnapshot()
}

func (u *UnitHook) Close() error {
	u.inProgressMetrics.Stop()
	return nil
}

type UnitMetrics struct {
	Unit   sources.SourceUnit     `json:"unit,omitempty"`
	Parent sources.JobProgressRef `json:"parent,omitempty"`
	// Start and end time for chunking this unit.
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	// Total number of chunks produced from this unit.
	TotalChunks uint64 `json:"total_chunks"`
	// Total number of bytes produced from this unit.
	TotalBytes uint64 `json:"total_bytes"`
	// All errors encountered by this unit.
	Errors []error `json:"errors"`
}

func (u UnitMetrics) IsFinished() bool {
	return u.EndTime != nil
}

// ElapsedTime is a convenience method that provides the elapsed time the job
// has been running. If it hasn't started yet, 0 is returned. If it has
// finished, the total time is returned.
func (u UnitMetrics) ElapsedTime() time.Duration {
	if u.StartTime == nil {
		return 0
	}
	if u.EndTime == nil {
		return time.Since(*u.StartTime)
	}
	return u.EndTime.Sub(*u.StartTime)
}
