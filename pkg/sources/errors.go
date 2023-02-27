package sources

import (
	"sync"
)

// ScanErrors is used to collect errors encountered while scanning.
// It ensures that errors are collected in a thread-safe manner.
type ScanErrors struct {
	mu     sync.RWMutex
	errors []error
}

// NewScanErrors creates a new thread safe error collector.
func NewScanErrors() *ScanErrors {
	return &ScanErrors{errors: make([]error, 0)}
}

// Add an error to the collection in a thread-safe manner.
func (s *ScanErrors) Add(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errors = append(s.errors, err)
}

// Count returns the number of errors collected.
func (s *ScanErrors) Count() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint64(len(s.errors))
}
