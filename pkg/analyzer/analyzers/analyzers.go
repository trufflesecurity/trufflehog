package analyzers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/fatih/color"
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
