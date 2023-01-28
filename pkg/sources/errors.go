package sources

import (
	"sync"
	"sync/atomic"
)

// ScanErrors is used to collect errors encountered while scanning.
// It ensures that errors are collected in a thread-safe manner.
type ScanErrors struct {
	count  uint64
	mu     sync.Mutex
	errors []error
}

// NewScanErrors creates a new thread safe error collector.
func NewScanErrors(projects int) *ScanErrors {
	return &ScanErrors{errors: make([]error, 0, projects)}
}

// Add an error to the collection in a thread-safe manner.
func (s *ScanErrors) Add(err error) {
	atomic.AddUint64(&s.count, 1)
	s.mu.Lock()
	s.errors = append(s.errors, err)
	s.mu.Unlock()
}

// Count returns the number of errors collected.
func (s *ScanErrors) Count() uint64 {
	return atomic.LoadUint64(&s.count)
}
