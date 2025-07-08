package sources

//go:generate mockgen --source=./job_progress.go --destination=mock_job_progress_test.go --package=sources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type JobProgressHook interface {
	// Start and End marks the overall start and end time for this job.
	Start(JobProgressRef, time.Time)
	End(JobProgressRef, time.Time)
	// StartEnumerating and EndEnumerating marks the start and end time for
	// calling the source's Enumerate method. If the source does not
	// support enumeration these methods will never be called.
	StartEnumerating(JobProgressRef, time.Time)
	EndEnumerating(JobProgressRef, time.Time)
	// StartUnitChunking and EndUnitChunking marks the start and end time
	// for calling the source's ChunkUnit method for a given unit. If the
	// source does not support enumeration these methods will never be
	// called.
	StartUnitChunking(JobProgressRef, SourceUnit, time.Time)
	EndUnitChunking(JobProgressRef, SourceUnit, time.Time)
	// ReportError is called when any general error is encountered, usually
	// from enumeration.
	ReportError(JobProgressRef, error)
	// ReportUnit is called when a unit has been enumerated. If the source
	// does not support enumeration this method will never be called.
	ReportUnit(JobProgressRef, SourceUnit)
	// ReportChunk is called when a chunk has been produced for the given
	// unit. The unit will be nil if the source does not support
	// enumeration.
	ReportChunk(JobProgressRef, SourceUnit, *Chunk)
	// Finish marks the job as done.
	Finish(JobProgressRef)
}

// JobProgressRef is a wrapper of a JobProgress for read-only access to its state.
// If the job supports it, the reference can also be used to cancel running via
// CancelRun.
type JobProgressRef struct {
	JobID       JobID    `json:"job_id"`
	SourceID    SourceID `json:"source_id"`
	SourceName  string   `json:"source_name"`
	jobProgress *JobProgress
}

// Snapshot returns a snapshot of the job's current metrics.
func (r *JobProgressRef) Snapshot() JobProgressMetrics {
	if r.jobProgress == nil {
		return JobProgressMetrics{}
	}
	return r.jobProgress.Snapshot()
}

// Done returns a channel that will block until the job has completed.
func (r *JobProgressRef) Done() <-chan struct{} {
	if r.jobProgress == nil {
		// Return a closed channel so it does not block.
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return r.jobProgress.Done()
}

// CancelRun requests that the job this is referencing is cancelled and stops
// running. This method will have no effect if the job does not allow
// cancellation.
func (r *JobProgressRef) CancelRun(cause error) {
	if r.jobProgress == nil || r.jobProgress.jobCancel == nil {
		return
	}
	r.jobProgress.jobCancel(cause)
}

// Fatal is a wrapper around error to differentiate non-fatal errors from fatal
// ones. A fatal error is typically from a finished context or any error
// returned from a source's Init, Chunks, Enumerate, or ChunkUnit methods.
type Fatal struct{ error }

func (f Fatal) Error() string { return fmt.Sprintf("fatal: %s", f.error.Error()) }
func (f Fatal) Unwrap() error { return f.error }

// ChunkError is a custom error type for errors encountered during chunking of
// a specific unit.
type ChunkError struct {
	Unit SourceUnit
	Err  error
}

func (f ChunkError) Error() string {
	unit, kind := "<nil>", SourceUnitKind("unit")
	if f.Unit != nil {
		unit, kind = f.Unit.SourceUnitID()
	}
	return fmt.Sprintf("error chunking %s %q: %s", kind, unit, f.Err.Error())
}
func (f ChunkError) Unwrap() error { return f.Err }

// JobProgress aggregates information about a run of a Source.
type JobProgress struct {
	// Unique identifiers for this job.
	JobID      JobID
	SourceID   SourceID
	SourceName string
	// Tracks whether the job is finished or not.
	ctx    context.Context
	cancel context.CancelFunc
	// Requests to cancel the job.
	jobCancel context.CancelCauseFunc
	// Metrics.
	metrics     JobProgressMetrics
	metricsLock sync.Mutex
	// Progress reported by the source.
	progress *Progress
	// Coarse grained hooks for adding extra functionality when events trigger.
	hooks []JobProgressHook
}

// JobProgressMetrics tracks the metrics of a job.
type JobProgressMetrics struct {
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	// Total number of units found by the Source.
	TotalUnits uint64 `json:"total_units,omitempty"`
	// Total number of units that have finished chunking.
	FinishedUnits uint64 `json:"finished_units,omitempty"`
	// Total number of chunks produced. This metric updates before the
	// chunk is sent on the output channel.
	TotalChunks uint64 `json:"total_chunks"`
	// All errors encountered.
	Errors []error `json:"errors"`
	// Set to true if the source supports enumeration and has finished
	// enumerating. If the source does not support enumeration, this field
	// is always false.
	DoneEnumerating bool `json:"done_enumerating,omitempty"`

	// Progress information reported by the source.
	SourcePercent           int64  `json:"source_percent,omitempty"`
	SourceMessage           string `json:"source_message,omitempty"`
	SourceEncodedResumeInfo string `json:"source_encoded_resume_info,omitempty"`
	SourceSectionsCompleted int32  `json:"source_sections_completed,omitempty"`
	SourceSectionsRemaining int32  `json:"source_sections_remaining,omitempty"`
}

// WithHooks adds hooks to be called when an event triggers.
func WithHooks(hooks ...JobProgressHook) func(*JobProgress) {
	return func(jp *JobProgress) { jp.hooks = append(jp.hooks, hooks...) }
}

// WithCancel allows cancelling the job by the JobProgressRef.
func WithCancel(cancel context.CancelCauseFunc) func(*JobProgress) {
	return func(jp *JobProgress) { jp.jobCancel = cancel }
}

// NewJobProgress creates a new job report for the given source and job ID.
func NewJobProgress(jobID JobID, sourceID SourceID, sourceName string, opts ...func(*JobProgress)) *JobProgress {
	ctx, cancel := context.WithCancel(context.Background())
	jp := &JobProgress{
		JobID:      jobID,
		SourceID:   sourceID,
		SourceName: sourceName,
		ctx:        ctx,
		cancel:     cancel,
	}
	for _, opt := range opts {
		opt(jp)
	}
	return jp
}

// TrackProgress informs the JobProgress of a Progress object and safely
// exposes its information in the Snapshots.
func (jp *JobProgress) TrackProgress(progress *Progress) {
	jp.progress = progress
}

// executeHooks is a helper method to execute all the hooks for the given
// closure.
func (jp *JobProgress) executeHooks(todo func(hook JobProgressHook)) {
	defer func(start time.Time) {
		elapsed := time.Since(start).Milliseconds()
		hooksExecTime.WithLabelValues().Observe(float64(elapsed))
	}(time.Now())
	for _, hook := range jp.hooks {
		// Execute hooks synchronously so they can provide
		// back-pressure to the source.
		todo(hook)
	}
}

// TODO: Comment all this mess. They are mostly implementing JobProgressHook but
// without the JobProgressRef parameter.
func (jp *JobProgress) Start(start time.Time) {
	jp.metricsLock.Lock()
	jp.metrics.StartTime = &start
	jp.metricsLock.Unlock()

	jp.executeHooks(func(hook JobProgressHook) { hook.Start(jp.Ref(), start) })
}
func (jp *JobProgress) End(end time.Time) {
	jp.metricsLock.Lock()
	jp.metrics.EndTime = &end
	jp.metricsLock.Unlock()

	jp.executeHooks(func(hook JobProgressHook) { hook.End(jp.Ref(), end) })
}
func (jp *JobProgress) Finish() {
	jp.cancel()
	jp.executeHooks(func(hook JobProgressHook) { hook.Finish(jp.Ref()) })
}
func (jp *JobProgress) Done() <-chan struct{} { return jp.ctx.Done() }
func (jp *JobProgress) ReportUnit(unit SourceUnit) {
	jp.metricsLock.Lock()
	jp.metrics.TotalUnits++
	jp.metricsLock.Unlock()
	jp.executeHooks(func(hook JobProgressHook) { hook.ReportUnit(jp.Ref(), unit) })
}
func (jp *JobProgress) ReportChunk(unit SourceUnit, chunk *Chunk) {
	jp.metricsLock.Lock()
	jp.metrics.TotalChunks++
	jp.metricsLock.Unlock()
	jp.executeHooks(func(hook JobProgressHook) { hook.ReportChunk(jp.Ref(), unit, chunk) })
}
func (jp *JobProgress) StartUnitChunking(unit SourceUnit, start time.Time) {
	// TODO: Record time.
	jp.executeHooks(func(hook JobProgressHook) { hook.StartUnitChunking(jp.Ref(), unit, start) })
}
func (jp *JobProgress) EndUnitChunking(unit SourceUnit, end time.Time) {
	// TODO: Record time.
	jp.metricsLock.Lock()
	jp.metrics.FinishedUnits++
	jp.metricsLock.Unlock()
	jp.executeHooks(func(hook JobProgressHook) { hook.EndUnitChunking(jp.Ref(), unit, end) })
}
func (jp *JobProgress) StartEnumerating(start time.Time) {
	// TODO: Record time.
	jp.executeHooks(func(hook JobProgressHook) { hook.StartEnumerating(jp.Ref(), start) })
}
func (jp *JobProgress) EndEnumerating(end time.Time) {
	jp.metricsLock.Lock()
	// TODO: Record time.
	jp.metrics.DoneEnumerating = true
	jp.metricsLock.Unlock()

	jp.executeHooks(func(hook JobProgressHook) { hook.EndEnumerating(jp.Ref(), end) })
}

// Snapshot safely gets the job's current metrics.
func (jp *JobProgress) Snapshot() JobProgressMetrics {
	jp.metricsLock.Lock()
	defer jp.metricsLock.Unlock()

	metrics := jp.metrics

	// Make a copy of the fields to make them read only.
	if jp.metrics.StartTime != nil {
		startTime := *jp.metrics.StartTime
		metrics.StartTime = &startTime
	}
	if jp.metrics.EndTime != nil {
		endTime := *jp.metrics.EndTime
		metrics.EndTime = &endTime
	}

	metrics.Errors = make([]error, len(metrics.Errors))
	copy(metrics.Errors, jp.metrics.Errors)

	if jp.progress != nil {
		jp.progress.mut.Lock()
		defer jp.progress.mut.Unlock()
		metrics.SourcePercent = jp.progress.PercentComplete
		metrics.SourceMessage = jp.progress.Message
		metrics.SourceEncodedResumeInfo = jp.progress.EncodedResumeInfo
		metrics.SourceSectionsCompleted = jp.progress.SectionsCompleted
		metrics.SourceSectionsRemaining = jp.progress.SectionsRemaining
	}

	return metrics
}

// ReportError adds a non-nil error to the aggregate of errors
// encountered during scanning.
func (jp *JobProgress) ReportError(err error) {
	if err == nil {
		return
	}
	jp.metricsLock.Lock()
	jp.metrics.Errors = append(jp.metrics.Errors, err)
	jp.metricsLock.Unlock()

	jp.executeHooks(func(hook JobProgressHook) { hook.ReportError(jp.Ref(), err) })
}

// Ref provides a read-only reference to the JobProgress.
func (jp *JobProgress) Ref() JobProgressRef {
	return JobProgressRef{
		SourceID:    jp.SourceID,
		JobID:       jp.JobID,
		SourceName:  jp.SourceName,
		jobProgress: jp,
	}
}

// EnumerationError joins all errors encountered during initialization or
// enumeration.
func (m JobProgressMetrics) EnumerationError() error {
	return errors.Join(m.Errors...)
}

// ChunkError joins all errors encountered during chunking.
func (m JobProgressMetrics) ChunkError() error {
	var aggregate []error
	for _, err := range m.Errors {
		var chunkErr ChunkError
		if ok := errors.As(err, &chunkErr); ok {
			aggregate = append(aggregate, err)
		}
	}
	return errors.Join(aggregate...)
}

// FatalError returns the first Fatal error, if any, encountered in the scan.
func (m JobProgressMetrics) FatalError() error {
	for _, err := range m.Errors {
		var fatalErr Fatal
		if found := errors.As(err, &fatalErr); found {
			return fatalErr
		}
	}
	return nil
}

// FatalErrors returns all of the encountered fatal errors joined together.
func (m JobProgressMetrics) FatalErrors() error {
	var aggregate []error
	for _, err := range m.Errors {
		var fatalErr Fatal
		if found := errors.As(err, &fatalErr); found {
			aggregate = append(aggregate, fatalErr)
		}
	}
	return errors.Join(aggregate...)
}

func (m JobProgressMetrics) PercentComplete() int {
	num := m.FinishedUnits
	den := m.TotalUnits
	if num == 0 && den == 0 {
		// Fallback to the source's self-reported percent complete if
		// the unit information isn't available.
		return int(m.SourcePercent)
	} else if den == 0 {
		// This should never happen. Return an invalid value so we can
		// trace it back to here if we ever see it.
		return -1
	}
	return int(num * 100 / den)
}

// ElapsedTime is a convenience method that provides the elapsed time the job
// has been running. If it hasn't started yet, 0 is returned. If it has
// finished, the total time is returned.
func (m JobProgressMetrics) ElapsedTime() time.Duration {
	if m.StartTime == nil {
		return 0
	}
	if m.EndTime == nil {
		return time.Since(*m.StartTime)
	}
	return m.EndTime.Sub(*m.StartTime)
}

// ErrorsFor returns all the errors for the given SourceUnit. If there are no
// errors, including the case that the unit has not been encountered, nil will
// be returned.
func (m JobProgressMetrics) ErrorsFor(unit SourceUnit) []error {
	var errs []error
	for _, err := range m.Errors {
		var chunkErr ChunkError
		if errors.As(err, &chunkErr) && chunkErr.Unit == unit {
			errs = append(errs, err)
		}
	}
	return errs
}
