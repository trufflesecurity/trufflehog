package analyzers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/fatih/color"
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
		Value  string
		Parent *Permission
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

// Sorted list of all available analyzers. Used for valid sub-commands and TUI
// selection. TODO: Change slice type to Analyzer interface when all available
// analyzers implement it.
var AvailableAnalyzers = []string{
	"Airbrake",
	"Asana",
	"Bitbucket",
	"GitHub",
	"GitLab",
	"HuggingFace",
	"Mailchimp",
	"Mailgun",
	"MySQL",
	"OpenAI",
	"Opsgenie",
	"Postgres",
	"Postman",
	"Sendgrid",
	"Shopify",
	"Slack",
	"Sourcegraph",
	"Square",
	"Stripe",
	"Twilio",
}

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
