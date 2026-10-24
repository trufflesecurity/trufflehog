package xai

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type stubResponse struct {
	status int
	body   string
}

type stubTransport map[string]stubResponse

func (s stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, ok := s[req.URL.String()]
	if !ok {
		res = stubResponse{status: http.StatusNotFound, body: "{}"}
	}
	return &http.Response{
		StatusCode: res.status,
		Body:       io.NopCloser(strings.NewReader(res.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func stubClient(apiKey, models stubResponse) *http.Client {
	return &http.Client{Transport: stubTransport{
		apiKeyEndpoint: apiKey,
		modelsEndpoint: models,
	}}
}

const modelsBody = `{"object":"list","data":[
	{"id":"grok-4","aliases":["grok-4-latest"],"owned_by":"xai","context_length":256000},
	{"id":"grok-3-mini","aliases":[],"owned_by":"xai"}
]}`

func apiKeyBody(acls string, blocked, disabled bool) string {
	b := map[bool]string{true: "true", false: "false"}
	return `{"acls":[` + acls + `],"api_key_blocked":` + b[blocked] + `,"api_key_disabled":` + b[disabled] +
		`,"api_key_id":"key-1","create_time":"2026-01-01T00:00:00Z","modified_by":"user-1",` +
		`"modify_time":"2026-01-01T00:00:00Z","name":"ci key","redacted_api_key":"xai-...abcd",` +
		`"team_blocked":false,"team_id":"team-1","user_id":"user-1"}`
}

func bindingSummary(result *analyzers.AnalyzerResult) []string {
	var out []string
	for _, b := range result.Bindings {
		out = append(out, b.Resource.Type+"|"+b.Resource.FullyQualifiedName+"|"+b.Permission.Value+"|"+b.Resource.Parent.FullyQualifiedName)
	}
	return out
}

func TestAnalyzePermissions(t *testing.T) {
	tests := []struct {
		name         string
		apiKey       stubResponse
		models       stubResponse
		wantErr      bool
		wantValid    bool
		wantBindings []string
		wantUnknown  []string
	}{
		{
			name:      "wildcard acls grant every listed model",
			apiKey:    stubResponse{http.StatusOK, apiKeyBody(`"api-key:endpoint:*","api-key:model:*"`, false, false)},
			models:    stubResponse{http.StatusOK, modelsBody},
			wantValid: true,
			wantBindings: []string{
				"endpoint|x.ai/team/team-1/endpoint/*|endpoint_access|x.ai/team/team-1",
				"model|x.ai/team/team-1/model/grok-4|model_access|x.ai/team/team-1",
				"model|x.ai/team/team-1/model/grok-3-mini|model_access|x.ai/team/team-1",
			},
		},
		{
			name:      "model acl matches by alias and keeps unlisted acl models",
			apiKey:    stubResponse{http.StatusOK, apiKeyBody(`"api-key:endpoint:chat","api-key:model:grok-4-latest","api-key:model:grok-2-image","team:admin"`, false, false)},
			models:    stubResponse{http.StatusOK, modelsBody},
			wantValid: true,
			wantBindings: []string{
				"endpoint|x.ai/team/team-1/endpoint/chat|endpoint_access|x.ai/team/team-1",
				"model|x.ai/team/team-1/model/grok-4|model_access|x.ai/team/team-1",
				"model|x.ai/team/team-1/model/grok-2-image|model_access|x.ai/team/team-1",
			},
			wantUnknown: []string{"team:admin"},
		},
		{
			name:      "models endpoint forbidden falls back to acl models",
			apiKey:    stubResponse{http.StatusOK, apiKeyBody(`"api-key:endpoint:chat","api-key:model:*"`, false, false)},
			models:    stubResponse{http.StatusForbidden, `{"error":"forbidden"}`},
			wantValid: true,
			wantBindings: []string{
				"endpoint|x.ai/team/team-1/endpoint/chat|endpoint_access|x.ai/team/team-1",
				"model|x.ai/team/team-1/model/*|model_access|x.ai/team/team-1",
			},
		},
		{
			name:      "blocked key is reported but not valid",
			apiKey:    stubResponse{http.StatusOK, apiKeyBody(`"api-key:endpoint:*","api-key:model:*"`, true, false)},
			wantValid: false,
		},
		{
			name:      "disabled key is reported but not valid",
			apiKey:    stubResponse{http.StatusOK, apiKeyBody(`"api-key:endpoint:*","api-key:model:*"`, false, true)},
			wantValid: false,
		},
		{
			name:    "invalid key",
			apiKey:  stubResponse{http.StatusUnauthorized, `{"error":"Incorrect API key provided"}`},
			wantErr: true,
		},
		{
			name:    "unexpected status",
			apiKey:  stubResponse{http.StatusInternalServerError, `{}`},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := analyzePermissions(context.Background(), stubClient(tt.apiKey, tt.models), "xai-test")
			if (err != nil) != tt.wantErr {
				t.Fatalf("analyzePermissions() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if info.Valid != tt.wantValid {
				t.Errorf("Valid = %v, want %v", info.Valid, tt.wantValid)
			}

			result := secretInfoToAnalyzerResult(info)
			if result.AnalyzerType != analyzers.AnalyzerTypeXAI {
				t.Errorf("AnalyzerType = %v, want %v", result.AnalyzerType, analyzers.AnalyzerTypeXAI)
			}
			if result.Metadata["Valid_Key"] != tt.wantValid || result.Metadata["key_name"] != "ci key" {
				t.Errorf("unexpected metadata: %v", result.Metadata)
			}
			if diff := cmp.Diff(tt.wantBindings, bindingSummary(result)); diff != "" {
				t.Errorf("bindings mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantUnknown, info.UnknownACLs); diff != "" {
				t.Errorf("unknown ACLs mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAnalyzer_MissingKey(t *testing.T) {
	_, err := Analyzer{}.Analyze(context.Background(), map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestAnalyzer_Analyze(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	tests := []struct {
		name    string
		secret  string
		wantErr bool
	}{
		{name: "valid xai key", secret: testSecrets.MustGetField("XAI")},
		{name: "invalid xai key", secret: testSecrets.MustGetField("XAI_INACTIVE"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Analyzer{Cfg: &config.Config{}}.Analyze(ctx, map[string]string{"key": tt.secret})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Analyzer.Analyze() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if got.Metadata["Valid_Key"] != true {
				t.Errorf("expected a usable key, got metadata %v", got.Metadata)
			}
			if len(got.Bindings) == 0 {
				t.Error("expected endpoint and model bindings")
			}
			for _, b := range got.Bindings {
				if _, ok := StringToPermission[b.Permission.Value]; !ok {
					t.Errorf("binding %s has unknown permission %q", b.Resource.FullyQualifiedName, b.Permission.Value)
				}
			}
		})
	}
}
