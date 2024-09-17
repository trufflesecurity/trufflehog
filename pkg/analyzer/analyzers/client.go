package analyzers

import (
	"fmt"
	"net/http"
	"os"
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

func NewAnalyzeClient(cfg *config.Config) *http.Client {
	if cfg == nil || !cfg.LoggingEnabled {
		return &http.Client{}
	}
	return &http.Client{
		Transport: LoggingRoundTripper{
			parent:  http.DefaultTransport,
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

	resp, err := r.parent.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// TODO: JSON
	logEntry := fmt.Sprintf("Date: %s, Method: %s, Path: %s, Status: %d\n", startTime.Format(time.RFC3339), req.Method, req.URL.Path, resp.StatusCode)

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

	return resp, nil
}
