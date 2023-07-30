package sources

//go:generate mockgen --source=./job_report.go --destination=mock_job_report_test.go --package=sources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type JobReportHook interface {
	// Start and End marks the overall start and end time for this job.
	Start(JobReportRef, time.Time)
	End(JobReportRef, time.Time)
	// StartEnumerating and EndEnumerating marks the start and end time for
	// calling the source's Enumerate method. If the source does not
	// support enumeration these methods will never be called.
	StartEnumerating(JobReportRef, time.Time)
	EndEnumerating(JobReportRef, time.Time)
	// StartUnitChunking and EndUnitChunking marks the start and end time
	// for calling the source's ChunkUnit method for a given unit. If the
	// source does not support enumeration these methods will never be
	// called.
	StartUnitChunking(JobReportRef, SourceUnit, time.Time)
	EndUnitChunking(JobReportRef, SourceUnit, time.Time)
	// ReportError is called when any general error is encountered, usually
	// from enumeration.
	ReportError(JobReportRef, error)
	// ReportUnit is called when a unit has been enumerated. If the source
	// does not support enumeration this method will never be called.
	ReportUnit(JobReportRef, SourceUnit)
	// ReportChunk is called when a chunk has been produced for the given
	// unit. The unit will be nil if the source does not support
	// enumeration.
	ReportChunk(JobReportRef, SourceUnit, *Chunk)
	// Finish marks the job as done.
	Finish(JobReportRef)
}

// JobReportRef is a wrapper of a JobReport for read-only access to its state.
type JobReportRef struct {
	SourceID  int64
	JobID     int64
	jobReport *JobReport
}

// Snapshot returns a snapshot of the job's current metrics.
func (r *JobReportRef) Snapshot() JobReportMetrics {
	if r.jobReport == nil {
		return JobReportMetrics{}
	}
	return r.jobReport.Snapshot()
}

// Done returns a channel that will block until the job has completed.
func (r *JobReportRef) Done() <-chan struct{} {
	if r.jobReport == nil {
		return nil
	}
	return r.jobReport.Done()
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
	unit SourceUnit
	err  error
}

func (f ChunkError) Error() string {
	return fmt.Sprintf("error chunking unit %q: %s", f.unit.SourceUnitID(), f.err.Error())
}
func (f ChunkError) Unwrap() error { return f.err }

// JobReport aggregates information about a run of a Source.
type JobReport struct {
	// Unique identifiers for this job.
	SourceID int64
	JobID    int64
	// Tracks whether the job is finished or not.
	ctx    context.Context
	cancel context.CancelFunc
	// Metrics.
	metrics     JobReportMetrics
	metricsLock sync.Mutex
	// Coarse grained hooks for adding extra functionality when events trigger.
	hooks []JobReportHook
}

// JobReportMetrics tracks the metrics of a job.
type JobReportMetrics struct {
	StartTime       time.Time
	EndTime         time.Time
	TotalUnits      uint64
	FinishedUnits   uint64
	TotalChunks     uint64
	Errors          []error
	DoneEnumerating bool
}

// WithHooks adds hooks to be called when an event triggers.
func WithHooks(hooks ...JobReportHook) func(*JobReport) {
	return func(jr *JobReport) { jr.hooks = append(jr.hooks, hooks...) }
}

// NewJobReport creates a new job report for the given source and job ID.
func NewJobReport(sourceID, jobID int64, opts ...func(*JobReport)) *JobReport {
	ctx, cancel := context.WithCancel(context.Background())
	jr := &JobReport{
		SourceID: sourceID,
		JobID:    jobID,
		ctx:      ctx,
		cancel:   cancel,
	}
	for _, opt := range opts {
		opt(jr)
	}
	return jr
}

// executeHooks is a helper method to execute all the hooks for the given
// closure.
func (jr *JobReport) executeHooks(todo func(hook JobReportHook)) {
	for _, hook := range jr.hooks {
		// TODO: Non-blocking?
		todo(hook)
	}
}

// TODO: Comment all this mess. They are mostly implementing JobReportHook but
// without the JobReportRef parameter.
func (jr *JobReport) Start(start time.Time) {
	jr.metricsLock.Lock()
	jr.metrics.StartTime = start
	jr.metricsLock.Unlock()

	jr.executeHooks(func(hook JobReportHook) { hook.Start(jr.Ref(), start) })
}
func (jr *JobReport) End(end time.Time) {
	jr.metricsLock.Lock()
	jr.metrics.EndTime = end
	jr.metricsLock.Unlock()

	jr.executeHooks(func(hook JobReportHook) { hook.End(jr.Ref(), end) })
}
func (jr *JobReport) Finish() {
	jr.cancel()
	jr.executeHooks(func(hook JobReportHook) { hook.Finish(jr.Ref()) })
}
func (jr *JobReport) Done() <-chan struct{} { return jr.ctx.Done() }
func (jr *JobReport) ReportUnit(unit SourceUnit) {
	atomic.AddUint64(&jr.metrics.TotalUnits, 1)
	jr.executeHooks(func(hook JobReportHook) { hook.ReportUnit(jr.Ref(), unit) })
}
func (jr *JobReport) ReportChunk(unit SourceUnit, chunk *Chunk) {
	atomic.AddUint64(&jr.metrics.TotalChunks, 1)
	jr.executeHooks(func(hook JobReportHook) { hook.ReportChunk(jr.Ref(), unit, chunk) })
}
func (jr *JobReport) StartUnitChunking(unit SourceUnit, start time.Time) {
	// TODO: Record time.
	jr.executeHooks(func(hook JobReportHook) { hook.StartUnitChunking(jr.Ref(), unit, start) })
}
func (jr *JobReport) EndUnitChunking(unit SourceUnit, end time.Time) {
	// TODO: Record time.
	atomic.AddUint64(&jr.metrics.FinishedUnits, 1)
	jr.executeHooks(func(hook JobReportHook) { hook.EndUnitChunking(jr.Ref(), unit, end) })
}
func (jr *JobReport) StartEnumerating(start time.Time) {
	// TODO: Record time.
	jr.executeHooks(func(hook JobReportHook) { hook.StartEnumerating(jr.Ref(), start) })
}
func (jr *JobReport) EndEnumerating(end time.Time) {
	jr.metricsLock.Lock()
	// TODO: Record time.
	jr.metrics.DoneEnumerating = true
	jr.metricsLock.Unlock()

	jr.executeHooks(func(hook JobReportHook) { hook.EndEnumerating(jr.Ref(), end) })
}

// Snapshot safely gets the job's current metrics.
func (jr *JobReport) Snapshot() JobReportMetrics {
	jr.metricsLock.Lock()
	defer jr.metricsLock.Unlock()
	return jr.metrics
}

// ReportError adds a non-nil error to the aggregate of errors
// encountered during scanning.
func (jr *JobReport) ReportError(err error) {
	if err == nil {
		return
	}
	jr.metricsLock.Lock()
	jr.metrics.Errors = append(jr.metrics.Errors, err)
	jr.metricsLock.Unlock()

	jr.executeHooks(func(hook JobReportHook) { hook.ReportError(jr.Ref(), err) })
}

// Ref provides a read-only reference to the JobReport.
func (jr *JobReport) Ref() JobReportRef {
	return JobReportRef{
		SourceID:  jr.SourceID,
		JobID:     jr.JobID,
		jobReport: jr,
	}
}

// EnumerationErrors joins all errors encountered during initialization or
// enumeration.
func (m JobReportMetrics) EnumerationError() error {
	return errors.Join(m.Errors...)
}

// ChunkErrors joins all errors encountered during chunking.
func (m JobReportMetrics) ChunkError() error {
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
func (m JobReportMetrics) FatalError() error {
	for _, err := range m.Errors {
		var fatalErr Fatal
		if found := errors.As(err, &fatalErr); found {
			return fatalErr
		}
	}
	return nil
}

// FatalErrors returns all of the encountered fatal errors joined together.
func (m JobReportMetrics) FatalErrors() error {
	var aggregate []error
	for _, err := range m.Errors {
		var fatalErr Fatal
		if found := errors.As(err, &fatalErr); found {
			aggregate = append(aggregate, fatalErr)
		}
	}
	return errors.Join(aggregate...)
}

func (m JobReportMetrics) PercentComplete() int {
	num := m.FinishedUnits
	den := m.TotalUnits
	if num == 0 && den == 0 {
		return 0
	}
	return int(num * 100 / den)
}
