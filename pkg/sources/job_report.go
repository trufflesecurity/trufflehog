package sources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type JobReportInspector interface {
	JobReporter
	JobInspector
}

type JobReporter interface {
	Start(time.Time)
	End(time.Time)
	StartUnitChunking(SourceUnit, time.Time)
	EndUnitChunking(SourceUnit, time.Time)
	Finish()
	ReportError(error)
	ReportUnit(SourceUnit)
	ReportChunk(SourceUnit, *Chunk)
	ReportChunkError(SourceUnit, error)
}

type JobInspector interface {
	ProducedChunks() uint64
	Complete() (uint64, int, bool)
	FatalError() error
	Errors() error
	Done() <-chan struct{}
}

// Fatal is a wrapper around error to differentiate non-fatal errors from fatal
// ones. A fatal error is typically from a finished context or any error
// returned from a source's Init, Chunks, Enumerate, or ChunkUnit methods.
type Fatal struct{ error }

func (f Fatal) Error() string { return fmt.Sprintf("fatal: %s", f.error.Error()) }
func (f Fatal) Unwrap() error { return f.error }

// JobReport aggregates information about a run of a Source.
type JobReport struct {
	// Tracks whether the job is finished or not.
	ctx    context.Context
	cancel context.CancelFunc
	// Unique identifiers for this job.
	SourceID int64
	JobID    int64
	// Metrics.
	StartTime       time.Time
	EndTime         time.Time
	TotalUnits      uint64
	FinishedUnits   uint64
	TotalChunks     uint64
	errors          ScanErrors
	chunkErrors     map[string][]error
	chunkErrorsLock sync.Mutex
	doneEnumerating bool
}

func NewJobReport(sourceID, jobID int64) *JobReport {
	ctx, cancel := context.WithCancel(context.Background())
	return &JobReport{
		SourceID: sourceID,
		JobID:    jobID,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (jr *JobReport) SetStart(start time.Time) { jr.StartTime = start }
func (jr *JobReport) SetEnd(end time.Time)     { jr.EndTime = end }
func (jr *JobReport) Finish()                  { jr.cancel() }
func (jr *JobReport) FinishEnumerating()       { jr.doneEnumerating = true }
func (jr *JobReport) Done() <-chan struct{}    { return jr.ctx.Done() }
func (jr *JobReport) ReportUnit(unit SourceUnit) {
	atomic.AddUint64(&jr.TotalUnits, 1)
}
func (jr *JobReport) ReportChunk(unit SourceUnit, chunk *Chunk) {
	atomic.AddUint64(&jr.TotalChunks, 1)
}
func (jr *JobReport) ProducedChunks() uint64 {
	return atomic.LoadUint64(&jr.TotalChunks)
}
func (jr *JobReport) Complete() (uint64, int, bool) {
	num := atomic.LoadUint64(&jr.FinishedUnits)
	den := atomic.LoadUint64(&jr.TotalUnits)
	if num == 0 || den == 0 {
		return den, 0, !jr.doneEnumerating
	}
	return den, int(num * 100 / den), !jr.doneEnumerating
}
func (jr *JobReport) StartUnitChunking(unit SourceUnit, start time.Time) {}
func (jr *JobReport) EndUnitChunking(unit SourceUnit, end time.Time) {
	atomic.AddUint64(&jr.FinishedUnits, 1)
}

// ReportError adds a non-nil error to the aggregate of errors
// encountered during scanning.
func (jr *JobReport) ReportError(err error) {
	if err == nil {
		return
	}
	jr.errors.Add(err)
}

// AddChunkError adds a non-nil error to the aggregate of errors encountered
// during chunking.
func (jr *JobReport) ReportChunkError(unit SourceUnit, err error) {
	if err == nil {
		return
	}
	id := ""
	if unit != nil {
		id = unit.SourceUnitID()
	}
	jr.chunkErrorsLock.Lock()
	defer jr.chunkErrorsLock.Unlock()
	if jr.chunkErrors == nil {
		jr.chunkErrors = make(map[string][]error)
	}
	jr.chunkErrors[id] = append(jr.chunkErrors[id], err)
}

// Errors joins all aggregated errors into one. If there were no errors, nil is
// returned. errors.Is can be used to check for specific errors.
func (jr *JobReport) Errors() error {
	return errors.Join(jr.EnumerationErrors(), jr.ChunkErrors())
}

// EnumerationErrors joins all errors encountered during initialization or
// enumeration.
func (jr *JobReport) EnumerationErrors() error {
	return jr.errors.Errors()
}

// ChunkErrors joins all errors encountered during chunking.
func (jr *JobReport) ChunkErrors() error {
	jr.chunkErrorsLock.Lock()
	defer jr.chunkErrorsLock.Unlock()
	// Check if we only have errors without unit information.
	if errs, ok := jr.chunkErrors[""]; ok && len(jr.chunkErrors) == 1 {
		return errors.Join(errs...)
	}

	aggregate := make([]error, 0, len(jr.chunkErrors))
	for id, errs := range jr.chunkErrors {
		err := fmt.Errorf("unit %q\n%w\n", id, errors.Join(errs...))
		aggregate = append(aggregate, err)
	}
	return errors.Join(aggregate...)
}

// FatalError returns the first Fatal error, if any, encountered in the scan.
func (jr *JobReport) FatalError() error {
	var err Fatal
	if found := errors.As(jr.Errors(), &err); found {
		return err
	}
	return nil
}
