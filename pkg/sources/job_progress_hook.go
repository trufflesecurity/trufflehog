package sources

import (
	"time"
)

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
