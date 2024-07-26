package analyzers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/pb/analyzerpb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type (
	Analyzer interface {
		Type() analyzerpb.AnalyzerType
		Analyze(ctx context.Context, credentialInfo map[string]string) (*AnalyzerResult, error)
	}

	// AnalyzerResult is the output of analysis.
	AnalyzerResult struct {
		AnalyzerType       analyzerpb.AnalyzerType
		Bindings           []Binding
		UnboundedResources []Resource
		Metadata           map[string]any
	}

	Resource struct {
		Name               string
		FullyQualifiedName string
		Type               string
		Metadata           map[string]any
		Parent             *Resource
	}

	Permission struct {
		Value       string
		AccessLevel string
		Parent      *Permission
	}

	Binding struct {
		Resource   Resource
		Permission Permission
	}
)

type PermissionType string

const (
	READ       PermissionType = "Read"
	WRITE      PermissionType = "Write"
	READ_WRITE PermissionType = "Read & Write"
	NONE       PermissionType = "None"
	ERROR      PermissionType = "Error"

	FullAccess string = "full_access"
)

type PermissionStatus struct {
	Value   bool
	IsError bool
}

type HttpStatusTest struct {
	URL     string
	Method  string
	Payload map[string]interface{}
	Params  map[string]string
	Valid   []int
	Invalid []int
	Type    PermissionType
	Status  PermissionStatus
	Risk    string
}

func (h *HttpStatusTest) RunTest(headers map[string]string) error {
	// If body data, marshal to JSON
	var data io.Reader
	if h.Payload != nil {
		jsonData, err := json.Marshal(h.Payload)
		if err != nil {
			return err
		}
		data = bytes.NewBuffer(jsonData)
	}

	// Create new HTTP request
	client := &http.Client{}
	req, err := http.NewRequest(h.Method, h.URL, data)
	if err != nil {
		return err
	}

	// Add custom headers if provided
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check response status code
	switch {
	case StatusContains(resp.StatusCode, h.Valid):
		h.Status.Value = true
	case StatusContains(resp.StatusCode, h.Invalid):
		h.Status.Value = false
	default:
		h.Status.IsError = true
	}
	return nil
}

type Scope struct {
	Name  string
	Tests []interface{}
}

func StatusContains(status int, vals []int) bool {
	for _, v := range vals {
		if status == v {
			return true
		}
	}
	return false
}

func GetWriterFromStatus(status PermissionType) func(a ...interface{}) string {
	switch status {
	case READ:
		return color.New(color.FgYellow).SprintFunc()
	case WRITE:
		return color.New(color.FgGreen).SprintFunc()
	case READ_WRITE:
		return color.New(color.FgGreen).SprintFunc()
	case NONE:
		return color.New().SprintFunc()
	case ERROR:
		return color.New(color.FgRed).SprintFunc()
	default:
		return color.New().SprintFunc()
	}
}

var GreenWriter = color.New(color.FgGreen).SprintFunc()
var YellowWriter = color.New(color.FgYellow).SprintFunc()
var RedWriter = color.New(color.FgRed).SprintFunc()
var DefaultWriter = color.New().SprintFunc()

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

// BindAllPermissions creates a Binding for each permission to the given
// resource.
func BindAllPermissions(r Resource, perms ...Permission) []Binding {
	bindings := make([]Binding, len(perms))
	for i, perm := range perms {
		bindings[i] = Binding{
			Resource:   r,
			Permission: perm,
		}
	}
	return bindings
}
