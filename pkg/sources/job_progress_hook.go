package sources

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// UnitHook implements JobProgressHook for tracking the progress of each
// individual unit.
type UnitHook struct {
	// Channel to send the metrics on when the unit has finished chunking.
	// NOTE: Hooks are synchronous! If writing to this channel blocks, the
	//       source manager cannot progress!
	FinishedMetrics chan<- UnitMetrics
	// Coarse grain locking.
	mu      sync.Mutex
	metrics map[string]*UnitMetrics
	NoopHook
}

// id is a helper method to generate an ID for the given job and unit.
func (u *UnitHook) id(ref JobProgressRef, unit SourceUnit) string {
	unitID := ""
	if unit != nil {
		unitID = unit.SourceUnitID()
	}
	return fmt.Sprintf("%d/%d/%s", ref.SourceID, ref.JobID, unitID)
}

// unitMetrics is a helper method to get the initialized *UnitMetrics object
// from the map. This method must be called with the lock already acquired.
func (u *UnitHook) unitMetrics(ref JobProgressRef, unit SourceUnit) *UnitMetrics {
	id := u.id(ref, unit)
	if u.metrics == nil {
		u.metrics = make(map[string]*UnitMetrics)
	}
	// Check if it already exists in the map.
	if unitMetrics := u.metrics[id]; unitMetrics != nil {
		return unitMetrics
	}
	// Create and save the metrics in the map.
	u.metrics[id] = &UnitMetrics{
		Unit:   unit,
		Parent: ref,
	}
	return u.metrics[id]
}

func (u *UnitHook) StartUnitChunking(ref JobProgressRef, unit SourceUnit, start time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.unitMetrics(ref, unit).StartTime = start
}

func (u *UnitHook) EndUnitChunking(ref JobProgressRef, unit SourceUnit, end time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()

	metrics := u.unitMetrics(ref, unit)
	metrics.EndTime = end
	u.FinishedMetrics <- *metrics
	delete(u.metrics, u.id(ref, unit))
}

func (u *UnitHook) ReportChunk(ref JobProgressRef, unit SourceUnit, chunk *Chunk) {
	u.mu.Lock()
	defer u.mu.Unlock()

	metrics := u.unitMetrics(ref, unit)
	metrics.TotalChunks++
	metrics.TotalBytes += uint64(len(chunk.Data))
}

func (u *UnitHook) ReportError(ref JobProgressRef, err error) {
	var chunkErr ChunkError
	if !errors.As(err, &chunkErr) {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	metrics := u.unitMetrics(ref, chunkErr.Unit)
	metrics.Errors = append(metrics.Errors, err)
}

func (u *UnitHook) Finish(ref JobProgressRef) {
	u.mu.Lock()
	defer u.mu.Unlock()
	// Clear out any metrics on this job. This covers the case for the
	// source running without unit support.
	prefix := u.id(ref, nil)
	for id, metric := range u.metrics {
		if !strings.HasPrefix(id, prefix) {
			continue
		}
		// If the unit is nil, the source does not support units.
		// Use the overall job metrics instead.
		if metric.Unit == nil {
			snap := ref.Snapshot()
			metric.StartTime = snap.StartTime
			metric.EndTime = snap.EndTime
			metric.Errors = snap.Errors
		}
		u.FinishedMetrics <- *metric
		delete(u.metrics, id)
	}
}

type UnitMetrics struct {
	Unit   SourceUnit
	Parent JobProgressRef
	// Start and end time for chunking this unit.
	StartTime time.Time
	EndTime   time.Time
	// Total number of chunks produced from this unit.
	TotalChunks uint64
	// Total number of bytes produced from this unit.
	TotalBytes uint64
	// All errors encountered by this unit.
	Errors []error
}

// ElapsedTime is a convenience method that provides the elapsed time the job
// has been running. If it hasn't started yet, 0 is returned. If it has
// finished, the total time is returned.
func (u UnitMetrics) ElapsedTime() time.Duration {
	if u.StartTime.IsZero() {
		return 0
	}
	if u.EndTime.IsZero() {
		return time.Since(u.StartTime)
	}
	return u.EndTime.Sub(u.StartTime)
}

// NoopHook implements JobProgressHook by doing nothing. This is useful for
// embedding in other structs to overwrite only the methods of the interface
// that you care about.
type NoopHook struct{}

func (NoopHook) Start(JobProgressRef, time.Time)                         {}
func (NoopHook) End(JobProgressRef, time.Time)                           {}
func (NoopHook) StartEnumerating(JobProgressRef, time.Time)              {}
func (NoopHook) EndEnumerating(JobProgressRef, time.Time)                {}
func (NoopHook) StartUnitChunking(JobProgressRef, SourceUnit, time.Time) {}
func (NoopHook) EndUnitChunking(JobProgressRef, SourceUnit, time.Time)   {}
func (NoopHook) ReportError(JobProgressRef, error)                       {}
func (NoopHook) ReportUnit(JobProgressRef, SourceUnit)                   {}
func (NoopHook) ReportChunk(JobProgressRef, SourceUnit, *Chunk)          {}
func (NoopHook) Finish(JobProgressRef)                                   {}
