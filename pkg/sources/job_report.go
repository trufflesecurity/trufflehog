package sources

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Fatal is a wrapper around error to differentiate non-fatal errors from fatal
// ones. A fatal error is typically from a finished context or any error
// returned from a source's Init, Chunks, Enumerate, or ChunkUnit methods.
type Fatal struct{ error }

func (f Fatal) Error() string { return fmt.Sprintf("fatal: %s", f.error.Error()) }
func (f Fatal) Unwrap() error { return f.error }

// JobReport aggregates information about a run of a Source.
type JobReport struct {
	SourceID        int64
	JobID           int64
	StartTime       time.Time
	EndTime         time.Time
	TotalChunks     uint64
	errors          ScanErrors
	chunkErrors     map[string][]error
	chunkErrorsLock sync.Mutex
}

// AddError adds a non-nil error to the aggregate of errors
// encountered during scanning.
func (jr *JobReport) AddError(err error) {
	if err == nil {
		return
	}
	jr.errors.Add(err)
}

// AddChunkError adds a non-nil error to the aggregate of errors encountered
// during chunking.
func (jr *JobReport) AddChunkError(unit SourceUnit, err error) {
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
