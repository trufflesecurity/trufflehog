package analyzers

import (
	"errors"
	"fmt"
	"testing"
)

func TestAnalysisErrorImplementsInterface(t *testing.T) {
	var _ AnalysisErrorInfo = (*AnalysisError)(nil)
}

func TestAnalysisErrorFields(t *testing.T) {
	orig := fmt.Errorf("connection refused")
	e := NewAnalysisError("Postgres", "connect", "Database", "localhost:5432", orig)

	if e.AnalyzerType() != "Postgres" {
		t.Errorf("AnalyzerType() = %q, want %q", e.AnalyzerType(), "Postgres")
	}
	if e.Operation() != "connect" {
		t.Errorf("Operation() = %q, want %q", e.Operation(), "connect")
	}
	if e.Service() != "Database" {
		t.Errorf("Service() = %q, want %q", e.Service(), "Database")
	}
	if e.Resource() != "localhost:5432" {
		t.Errorf("Resource() = %q, want %q", e.Resource(), "localhost:5432")
	}
}

func TestAnalysisErrorUnwrap(t *testing.T) {
	orig := fmt.Errorf("timeout")
	e := NewAnalysisError("GitHub", "authenticate", "API", "", orig)

	if !errors.Is(e, orig) {
		t.Error("errors.Is should find the original error")
	}
}

func TestAnalysisErrorAs(t *testing.T) {
	orig := fmt.Errorf("bad key")
	e := NewAnalysisError("Airbrake", "validate_credentials", "config", "", orig)

	// Wrap it further
	wrapped := fmt.Errorf("analyze failed: %w", e)

	var ae AnalysisErrorInfo
	if !errors.As(wrapped, &ae) {
		t.Fatal("errors.As should find AnalysisErrorInfo in wrapped error")
	}
	if ae.AnalyzerType() != "Airbrake" {
		t.Errorf("AnalyzerType() = %q, want %q", ae.AnalyzerType(), "Airbrake")
	}
	if ae.Operation() != "validate_credentials" {
		t.Errorf("Operation() = %q, want %q", ae.Operation(), "validate_credentials")
	}
}

func TestAnalysisErrorMessage(t *testing.T) {
	orig := fmt.Errorf("401 unauthorized")
	e := NewAnalysisError("Slack", "authenticate", "API", "workspace-123", orig)

	expected := "Slack analysis failed: authenticate on API (resource: workspace-123): 401 unauthorized"
	if e.Error() != expected {
		t.Errorf("Error() = %q, want %q", e.Error(), expected)
	}
}

func TestAnalysisErrorMessageNilError(t *testing.T) {
	e := NewAnalysisError("MySQL", "connect", "Database", "db.example.com", nil)

	expected := "MySQL analysis failed: connect on Database (resource: db.example.com)"
	if e.Error() != expected {
		t.Errorf("Error() = %q, want %q", e.Error(), expected)
	}
}
