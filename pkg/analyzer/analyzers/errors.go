package analyzers

import "fmt"

// AnalysisErrorInfo is implemented by errors that provide structured context
// about analysis failures. This allows downstream consumers (e.g., the scanner)
// to extract metadata for structured error storage without depending on
// concrete error types.
type AnalysisErrorInfo interface {
	error
	AnalyzerType() string
	Operation() string // "validate_credentials", "authenticate", "analyze_permissions", "connect", "ping"
	Service() string   // "config", "API", "OAuth", "Database"
	Resource() string  // account ID, endpoint URL, or other identifier
}

// AnalysisError represents a structured error from an analyzer.
type AnalysisError struct {
	analyzerType string
	operation    string
	service      string
	resource     string
	err          error
}

// NewAnalysisError creates a new AnalysisError.
func NewAnalysisError(analyzerType, operation, service, resource string, err error) *AnalysisError {
	return &AnalysisError{
		analyzerType: analyzerType,
		operation:    operation,
		service:      service,
		resource:     resource,
		err:          err,
	}
}

func (e *AnalysisError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%s analysis failed: %s on %s (resource: %s): %v",
			e.analyzerType, e.operation, e.service, e.resource, e.err)
	}
	return fmt.Sprintf("%s analysis failed: %s on %s (resource: %s)",
		e.analyzerType, e.operation, e.service, e.resource)
}

func (e *AnalysisError) Unwrap() error    { return e.err }
func (e *AnalysisError) AnalyzerType() string { return e.analyzerType }
func (e *AnalysisError) Operation() string    { return e.operation }
func (e *AnalysisError) Service() string      { return e.service }
func (e *AnalysisError) Resource() string     { return e.resource }
