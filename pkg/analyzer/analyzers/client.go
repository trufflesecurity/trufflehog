package analyzers

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

type AnalyzeClient struct {
	http.Client
	LoggingEnabled bool
	LogFile        string
}

func CreateLogFileName(baseName string) string {
	// Get the current time
	currentTime := time.Now()

	// Format the time as "2024_06_30_07_15_30"
	timeString := currentTime.Format("2006_01_02_15_04_05")

	// Create the log file name
	logFileName := fmt.Sprintf("%s_%s.log", timeString, baseName)
	return logFileName
}

// This returns a client that is restricted and filters out unsafe requests returning a success status code.
func NewAnalyzeClient(cfg *config.Config) *http.Client {
	client := &http.Client{
		Transport: AnalyzerRoundTripper{parent: http.DefaultTransport},
	}
	if cfg == nil || !cfg.LoggingEnabled {
		return client
	}
	return &http.Client{
		Transport: LoggingRoundTripper{
			parent:  client.Transport,
			logFile: cfg.LogFile,
		},
	}
}

// This returns a client that is unrestricted and does not filter out unsafe requests returning a success status code.
func NewAnalyzeClientUnrestricted(cfg *config.Config) *http.Client {
	client := &http.Client{
		Transport: http.DefaultTransport,
	}
	if cfg == nil || !cfg.LoggingEnabled {
		return client
	}
	return &http.Client{
		Transport: LoggingRoundTripper{
			parent:  client.Transport,
			logFile: cfg.LogFile,
		},
	}
}

type LoggingRoundTripper struct {
	parent http.RoundTripper
	// TODO: io.Writer
	logFile string
}

func (r LoggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	startTime := time.Now()

	resp, parentErr := r.parent.RoundTrip(req)
	if resp == nil {
		return resp, parentErr
	}

	// TODO: JSON
	var logEntry string
	if parentErr != nil {
		logEntry = fmt.Sprintf("Date: %s, Method: %s, Path: %s, Status: %d, Error: %s\n",
			startTime.Format(time.RFC3339),
			req.Method,
			req.URL.Path,
			resp.StatusCode,
			parentErr.Error(),
		)
	} else {
		logEntry = fmt.Sprintf("Date: %s, Method: %s, Path: %s, Status: %d\n",
			startTime.Format(time.RFC3339),
			req.Method,
			req.URL.Path,
			resp.StatusCode,
		)
	}

	// Open log file in append mode.
	file, err := os.OpenFile(r.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return resp, fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	// Write log entry to file.
	if _, err := file.WriteString(logEntry); err != nil {
		return resp, fmt.Errorf("failed to write log entry to file: %w", err)
	}

	return resp, parentErr
}

type AnalyzerRoundTripper struct {
	parent http.RoundTripper
}

func (r AnalyzerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.parent.RoundTrip(req)
	if err != nil || IsMethodSafe(req.Method) {
		return resp, err
	}
	// Check that unsafe methods did NOT return a valid status code.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, fmt.Errorf("non-safe request returned success")
	}
	return resp, nil
}

// IsMethodSafe is a helper method to check whether the HTTP method is safe according to MDN Web Docs.
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods#safe_idempotent_and_cacheable_request_methods
func IsMethodSafe(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}
