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
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/pb/resourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type (
	Analyzer interface {
		Type() analyzerpb.SecretType
		Analyze(ctx context.Context, key string, extraData map[string]string) (*AnalyzerResult, error)
	}

	// AnalyzerResult is the output of analysis.
	AnalyzerResult struct {
		ResourcePermissions []ResourcePermission
		SecretMetadata      map[string]string
	}

	// ResourcePermission is a tuple describing a resource and the
	// permissions associated with it.
	ResourcePermission struct {
		ResourceTree ResourceTree
		Permissions  []Permission
	}

	// Resource represents an entity that a secret has permissions for. It
	// is recursive to capture the hierarchical nature, however whether
	// permissions apply to the children of resources is dependent on the
	// platform.
	ResourceTree struct {
		Parent   *ResourceTree
		Resource *resourcespb.Resource
	}

	Permission string
)

type PermissionType string

const (
	READ       PermissionType = "Read"
	WRITE      PermissionType = "Write"
	READ_WRITE PermissionType = "Read & Write"
	NONE       PermissionType = "None"
	ERROR      PermissionType = "Error"
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
