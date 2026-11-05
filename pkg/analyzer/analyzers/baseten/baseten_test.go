package baseten

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const testKey = "b10_AbCd1234.k9Xq2Lm7Np4Rs8Tv1Wy5Za3Bc6De0Fg2"

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

func stubClient(user, org, keys stubResponse) *http.Client {
	return &http.Client{Transport: stubTransport{
		currentUserEndpoint:  user,
		organizationEndpoint: org,
		apiKeysEndpoint:      keys,
	}}
}

var (
	serviceAccountUser = stubResponse{http.StatusOK, `{"user_id":"sa1","email":null,"name":"Workspace service account","workspace_name":"acme"}`}
	personalUser       = stubResponse{http.StatusOK, `{"user_id":"u1","email":"dev@example.com","name":"Dev","workspace_name":"acme"}`}
	orgOK              = stubResponse{http.StatusOK, `{"org_id":"org1","name":"acme","created_at":"2026-01-01T00:00:00Z"}`}
	forbidden          = stubResponse{http.StatusForbidden, `{"code":"PERMISSION_DENIED","message":"Authorization error"}`}
)

func keysBody(keys ...string) stubResponse {
	return stubResponse{http.StatusOK, `{"keys":[` + strings.Join(keys, ",") + `]}`}
}

const (
	selfOrgKey      = `{"prefix":"b10_AbCd1234","name":"org key","type":"WORKSPACE_MANAGE_API_KEYS","team_name":null,"created_at":"2026-01-01T00:00:00Z","last_used_at":null,"owner":null}`
	selfPersonalKey = `{"prefix":"b10_AbCd1234","name":"laptop","type":"PERSONAL","created_at":"2026-01-01T00:00:00Z","owner":{"user_id":"u1","email":"dev@example.com","name":"Dev"}}`
	selfInvokeKey   = `{"prefix":"b10_AbCd1234","name":"ci","type":"WORKSPACE_INVOKE","model_ids":["m1","m2"],"team_name":"ml","created_at":"2026-01-01T00:00:00Z"}`
	otherTeamKey    = `{"prefix":"b10_Team0001","name":"ci","type":"WORKSPACE_MANAGE_ALL","team_name":"ml","created_at":"2026-01-01T00:00:00Z"}`
	otherPersonal   = `{"prefix":"b10_Pers0001","type":"PERSONAL","created_at":"2026-01-01T00:00:00Z","owner":{"user_id":"u2","email":"other@example.com","name":"Other"}}`
)

func bindingSummary(result *analyzers.AnalyzerResult) []string {
	var out []string
	for _, b := range result.Bindings {
		parent := ""
		if b.Resource.Parent != nil {
			parent = b.Resource.Parent.FullyQualifiedName
		}
		out = append(out, b.Resource.Type+"|"+b.Resource.FullyQualifiedName+"|"+b.Permission.Value+"|"+parent)
	}
	return out
}

func TestAnalyzePermissions(t *testing.T) {
	tests := []struct {
		name         string
		user         stubResponse
		org          stubResponse
		keys         stubResponse
		wantErr      bool
		wantCategory string
		wantKeyType  string
		wantBindings []string
	}{
		{
			name:         "team key cannot list api keys",
			user:         serviceAccountUser,
			org:          orgOK,
			keys:         forbidden,
			wantCategory: categoryTeam,
		},
		{
			name:         "organization key manages every other key",
			user:         serviceAccountUser,
			org:          orgOK,
			keys:         keysBody(selfOrgKey, otherTeamKey, otherPersonal),
			wantCategory: categoryOrganization,
			wantKeyType:  keyTypeManageAPIKeys,
			wantBindings: []string{
				"organization|baseten.co/organization/org1|manage_api_keys|",
				"api_key|baseten.co/organization/org1/api_key/b10_Team0001|manage_api_keys|baseten.co/organization/org1",
				"api_key|baseten.co/organization/org1/api_key/b10_Pers0001|manage_api_keys|baseten.co/organization/org1",
			},
		},
		{
			name:         "personal key has full access to the organization",
			user:         personalUser,
			org:          orgOK,
			keys:         keysBody(selfPersonalKey),
			wantCategory: categoryPersonal,
			wantKeyType:  keyTypePersonal,
			wantBindings: []string{"organization|baseten.co/organization/org1|full_access|"},
		},
		{
			name:         "personal key missing from listing is classified by email",
			user:         personalUser,
			org:          orgOK,
			keys:         keysBody(otherPersonal),
			wantCategory: categoryPersonal,
		},
		{
			name:         "model scoped key binds each model under its team",
			user:         serviceAccountUser,
			org:          orgOK,
			keys:         keysBody(selfInvokeKey),
			wantCategory: categoryTeam,
			wantKeyType:  keyTypeInvoke,
			wantBindings: []string{
				"model|baseten.co/organization/org1/team/ml/model/m1|invoke|baseten.co/organization/org1/team/ml",
				"model|baseten.co/organization/org1/team/ml/model/m2|invoke|baseten.co/organization/org1/team/ml",
			},
		},
		{
			name:         "organization falls back to workspace name",
			user:         personalUser,
			org:          forbidden,
			keys:         keysBody(selfPersonalKey),
			wantCategory: categoryPersonal,
			wantKeyType:  keyTypePersonal,
			wantBindings: []string{"organization|baseten.co/organization/acme|full_access|"},
		},
		{
			name:    "invalid key",
			user:    stubResponse{http.StatusUnauthorized, `{}`},
			wantErr: true,
		},
		{
			name:    "unexpected status listing keys",
			user:    serviceAccountUser,
			org:     orgOK,
			keys:    stubResponse{http.StatusInternalServerError, `{}`},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := analyzePermissions(context.Background(), stubClient(tt.user, tt.org, tt.keys), testKey)
			if (err != nil) != tt.wantErr {
				t.Fatalf("analyzePermissions() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if info.Category != tt.wantCategory {
				t.Errorf("Category = %q, want %q", info.Category, tt.wantCategory)
			}

			result := secretInfoToAnalyzerResult(info)
			if result.AnalyzerType != analyzers.AnalyzerTypeBaseten {
				t.Errorf("AnalyzerType = %v", result.AnalyzerType)
			}
			if got := result.Metadata["key_category"]; got != tt.wantCategory {
				t.Errorf("key_category = %v, want %q", got, tt.wantCategory)
			}
			if got, _ := result.Metadata["key_type"].(string); got != tt.wantKeyType {
				t.Errorf("key_type = %q, want %q", got, tt.wantKeyType)
			}
			if diff := cmp.Diff(tt.wantBindings, bindingSummary(result)); diff != "" {
				t.Errorf("bindings mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAnalyze_MissingKey(t *testing.T) {
	if _, err := (Analyzer{}).Analyze(context.Background(), map[string]string{}); err == nil {
		t.Fatal("expected error for missing key")
	}
}
