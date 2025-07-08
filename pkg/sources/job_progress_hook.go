package sources

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// UnitHook implements JobProgressHook for tracking the progress of each
// individual unit.
type UnitHook struct {
	metrics         map[string]*UnitMetrics
	mu              sync.Mutex
	finishedMetrics chan UnitMetrics
	logBackPressure func()
	NoopHook
}

type UnitHookOpt func(*UnitHook)

// WithUnitHookFinishBufferSize sets the buffer size for handling finished
// metrics (default is 1024). If the buffer fills, then scanning will stop
// until there is room.
func WithUnitHookFinishBufferSize(buf int) UnitHookOpt {
	return func(hook *UnitHook) {
		hook.finishedMetrics = make(chan UnitMetrics, buf)
	}
}

func NewUnitHook(ctx context.Context, opts ...UnitHookOpt) (*UnitHook, <-chan UnitMetrics) {
	var once sync.Once
	hook := UnitHook{
		metrics:         make(map[string]*UnitMetrics, runtime.NumCPU()),
		finishedMetrics: make(chan UnitMetrics, 1024),
		logBackPressure: func() {
			once.Do(func() {
				ctx.Logger().Info("back pressure detected in unit hook")
			})
		},
	}
	for _, opt := range opts {
		opt(&hook)
	}
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				hooksChannelSize.WithLabelValues().Set(float64(len(hook.finishedMetrics)))
			case <-ctx.Done():
				return
			}
		}
	}()
	return &hook, hook.finishedMetrics
}

// id is a helper method to generate an ID for the given job and unit.
func (u *UnitHook) id(ref JobProgressRef, unit SourceUnit) string {
	unitID := ""
	if unit != nil {
		id, kind := unit.SourceUnitID()
		unitID = fmt.Sprintf("%s:%s", kind, id)
	}
	return fmt.Sprintf("%d/%d/%s", ref.SourceID, ref.JobID, unitID)
}

func (u *UnitHook) ejectFinishedMetrics(metrics UnitMetrics) {
	// Intentionally block the hook from returning to supply back-pressure
	// to the source.
	select {
	case u.finishedMetrics <- metrics:
		return
	default:
		u.logBackPressure()
	}
	u.finishedMetrics <- metrics
}

func (u *UnitHook) StartUnitChunking(ref JobProgressRef, unit SourceUnit, start time.Time) {
	id := u.id(ref, unit)
	u.mu.Lock()
	defer u.mu.Unlock()

	u.metrics[id] = &UnitMetrics{
		Unit:      unit,
		Parent:    ref,
		StartTime: &start,
	}
}

func (u *UnitHook) EndUnitChunking(ref JobProgressRef, unit SourceUnit, end time.Time) {
	id := u.id(ref, unit)

	metrics, ok := u.finishUnit(id)
	if !ok {
		return
	}
	metrics.EndTime = &end
	u.ejectFinishedMetrics(*metrics)
}

func (u *UnitHook) finishUnit(id string) (*UnitMetrics, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()

	metrics, ok := u.metrics[id]
	if !ok {
		return nil, false
	}
	delete(u.metrics, id)
	return metrics, true
}

func (u *UnitHook) ReportChunk(ref JobProgressRef, unit SourceUnit, chunk *Chunk) {
	id := u.id(ref, unit)
	u.mu.Lock()
	defer u.mu.Unlock()

	metrics, ok := u.metrics[id]
	if !ok && unit != nil {
		// The unit has been evicted.
		return
	} else if !ok && unit == nil {
		// This is a chunk from a non-unit source.
		metrics = &UnitMetrics{
			Unit:      nil,
			Parent:    ref,
			StartTime: ref.Snapshot().StartTime,
		}
		u.metrics[id] = metrics
	}
	metrics.TotalChunks++
	metrics.TotalBytes += uint64(len(chunk.Data))
}

func (u *UnitHook) ReportError(ref JobProgressRef, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	// Always add the error to the nil unit if it exists.
	if metrics, ok := u.metrics[u.id(ref, nil)]; ok {
		metrics.Errors = append(metrics.Errors, err)
	}

	// Check if it's a ChunkError for a specific unit.
	var chunkErr ChunkError
	if !errors.As(err, &chunkErr) {
		return
	}
	id := u.id(ref, chunkErr.Unit)

	metrics, ok := u.metrics[id]
	if !ok {
		return
	}
	metrics.Errors = append(metrics.Errors, err)
}

func (u *UnitHook) Finish(ref JobProgressRef) {
	// Clear out any metrics on this job. This covers the case for the
	// source running without unit support.
	id := u.id(ref, nil)
	metrics, ok := u.finishUnit(id)
	if !ok {
		return
	}
	snap := ref.Snapshot()
	metrics.StartTime = snap.StartTime
	metrics.EndTime = snap.EndTime
	metrics.Errors = snap.Errors
	u.ejectFinishedMetrics(*metrics)
}

// InProgressSnapshot gets all the currently active metrics across all jobs.
func (u *UnitHook) InProgressSnapshot() []UnitMetrics {
	u.mu.Lock()
	defer u.mu.Unlock()
	output := make([]UnitMetrics, 0, len(u.metrics))
	for _, metrics := range u.metrics {
		output = append(output, *metrics)
	}
	return output
}

func (u *UnitHook) Close() error {
	close(u.finishedMetrics)
	return nil
}

type UnitMetrics struct {
	Unit   SourceUnit     `json:"unit,omitempty"`
	Parent JobProgressRef `json:"parent,omitempty"`
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
