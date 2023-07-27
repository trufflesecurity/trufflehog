package sources

import (
	"errors"
	"sync"
	"time"
)

// JobReport aggregates information about a run of a Source.
type JobReport struct {
	SourceID    int64
	JobID       int64
	StartTime   time.Time
	EndTime     time.Time
	TotalChunks uint64
	errors      []error
	errorsLock  sync.Mutex
}

// AddError adds a non-nil error to the aggregate of errors encountered during
// scanning.
func (jr *JobReport) AddError(err error) {
	if err == nil {
		return
	}
	jr.errorsLock.Lock()
	defer jr.errorsLock.Unlock()
	jr.errors = append(jr.errors, err)
}

// Errors joins all aggregated errors into one. If there were no errors, nil is
// returned. errors.Is can be used to check for specific errors.
func (jr *JobReport) Errors() error {
	jr.errorsLock.Lock()
	defer jr.errorsLock.Unlock()
	return errors.Join(jr.errors...)
}
