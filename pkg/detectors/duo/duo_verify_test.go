package duo

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

const (
	testHost = "api-1a2b3c4d.duosecurity.com"
	testIKey = "DIABCDEFGHIJ12345678"
	testSKey = "abcdefghijABCDEFGHIJ0123456789abcdefghij"
)

// Messages Duo sends with each error code, as seen from live responses.
var duoMessages = map[int]string{
	40101: "Missing request credentials",
	40102: "Invalid identity in request credentials",
	40103: "Invalid signature in request credentials",
	40301: "Access forbidden",
}

var errNetwork = errors.New("network unreachable")

// duoResponse is the fake answer for one API path. A nil value means the transport
// fails for that path.
type duoResponse *fakeReply

type fakeReply struct {
	status int
	body   string
}

// duoError answers with a Duo error body; the HTTP status is its first three digits.
func duoError(c int) duoResponse {
	return &fakeReply{
		status: c / 100,
		body:   fmt.Sprintf(`{"code": %d, "message": %q, "stat": "FAIL"}`, c, duoMessages[c]),
	}
}

// raw answers with a status and a body that is not a Duo error.
func raw(status int, body string) duoResponse { return &fakeReply{status: status, body: body} }

var okReply = raw(http.StatusOK, `{"stat": "OK", "response": {}}`)

type fakeDuo struct {
	mu       sync.Mutex
	requests map[string]*http.Request
}

func newFakeDuoClient(t *testing.T, admin, auth duoResponse) (*http.Client, *fakeDuo) {
	t.Helper()
	fake := &fakeDuo{requests: map[string]*http.Request{}}
	responses := map[string]duoResponse{adminAPIPath: admin, authAPIPath: auth}
	client := &http.Client{
		Transport: common.FakeTransport{
			CreateResponse: func(req *http.Request) (*http.Response, error) {
				fake.mu.Lock()
				fake.requests[req.URL.Path] = req
				fake.mu.Unlock()

				resp, found := responses[req.URL.Path]
				if !found {
					t.Errorf("unexpected request path %s", req.URL.Path)
					return nil, errNetwork
				}
				if resp == nil {
					return nil, errNetwork
				}
				return &http.Response{
					Request:    req,
					StatusCode: resp.status,
					Body:       io.NopCloser(strings.NewReader(resp.body)),
				}, nil
			},
		},
	}
	return client, fake
}

func (f *fakeDuo) called(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, found := f.requests[path]
	return found
}

func testData() []byte {
	return []byte("DUO_APIHOST=" + testHost + " DUO_IKEY=" + testIKey + " DUO_SKEY=" + testSKey)
}

func TestDuo_Verification_Outcomes(t *testing.T) {
	tests := []struct {
		name            string
		admin           duoResponse
		auth            duoResponse
		wantVerified    bool
		wantApplication string
		wantErr         bool
		wantAuthCalled  bool
	}{
		// Verified: an API accepted the credentials.
		{
			name:  "admin 200 verifies an Admin API key",
			admin: okReply, auth: duoError(40301),
			wantVerified: true, wantApplication: adminApplication,
		},
		{
			name:  "admin 40102, auth 200 verifies an Auth API key",
			admin: duoError(40102), auth: okReply,
			wantVerified: true, wantApplication: authApplication, wantAuthCalled: true,
		},
		{
			name:  "admin 40301, auth 200 verifies an Auth API key",
			admin: duoError(40301), auth: okReply,
			wantVerified: true, wantApplication: authApplication, wantAuthCalled: true,
		},

		// Invalid: an API recognized the integration key and rejected the secret key.
		{
			name:  "admin 40103, auth 40301 is an Admin API key with a wrong secret",
			admin: duoError(40103), auth: duoError(40301),
			wantApplication: adminApplication, wantAuthCalled: true,
		},
		{
			name:  "admin 40102, auth 40103 is an Auth API key with a wrong secret",
			admin: duoError(40102), auth: duoError(40103),
			wantApplication: adminApplication, wantAuthCalled: true,
		},
		{
			name:  "admin network error, auth 40103 is invalid",
			admin: nil, auth: duoError(40103),
			wantApplication: adminApplication, wantAuthCalled: true,
		},
		{
			name:  "admin 40103, auth network error is invalid",
			admin: duoError(40103), auth: nil,
			wantApplication: adminApplication, wantAuthCalled: true,
		},

		// Indeterminate: no response judged the secret key.
		{
			name:  "admin 40102, auth 40301 is another integration type",
			admin: duoError(40102), auth: duoError(40301),
			wantApplication: adminApplication, wantErr: true, wantAuthCalled: true,
		},
		{
			name:  "admin 40102, auth 40102 is unknown to both APIs",
			admin: duoError(40102), auth: duoError(40102),
			wantApplication: adminApplication, wantErr: true, wantAuthCalled: true,
		},
		{
			name:  "admin 40301, auth 40301 is an Admin API key without permission",
			admin: duoError(40301), auth: duoError(40301),
			wantApplication: adminApplication, wantErr: true, wantAuthCalled: true,
		},
		{
			name:  "40101 means the request was malformed",
			admin: duoError(40101), auth: duoError(40101),
			wantApplication: adminApplication, wantErr: true, wantAuthCalled: true,
		},
		{
			name:  "401 without a Duo error body is not a verdict",
			admin: raw(http.StatusUnauthorized, `<html>Unauthorized</html>`), auth: raw(http.StatusUnauthorized, ``),
			wantApplication: adminApplication, wantErr: true, wantAuthCalled: true,
		},
		{
			name:  "admin 40102, auth network error is indeterminate",
			admin: duoError(40102), auth: nil,
			wantApplication: adminApplication, wantErr: true, wantAuthCalled: true,
		},
		{
			name:  "admin 500 is indeterminate",
			admin: raw(http.StatusInternalServerError, ``), auth: duoError(40301),
			wantApplication: adminApplication, wantErr: true, wantAuthCalled: true,
		},
		{
			name:  "both network errors are indeterminate",
			admin: nil, auth: nil,
			wantApplication: adminApplication, wantErr: true, wantAuthCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, fake := newFakeDuoClient(t, tt.admin, tt.auth)
			s := Scanner{client: client}

			results, err := s.FromData(context.Background(), true, testData())
			if err != nil {
				t.Fatalf("FromData error: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			r := results[0]
			if r.Verified != tt.wantVerified {
				t.Errorf("Verified = %v, want %v", r.Verified, tt.wantVerified)
			}
			if tt.wantErr && r.VerificationError() == nil {
				t.Error("expected a verification error, got nil")
			}
			if !tt.wantErr && r.VerificationError() != nil {
				t.Errorf("unexpected verification error: %v", r.VerificationError())
			}
			if got := r.ExtraData["application"]; got != tt.wantApplication {
				t.Errorf("ExtraData application = %q, want %q", got, tt.wantApplication)
			}
			if got := r.SecretParts["application"]; got != tt.wantApplication {
				t.Errorf("SecretParts application = %q, want %q", got, tt.wantApplication)
			}
			if !fake.called(adminAPIPath) {
				t.Error("admin API was not called")
			}
			if got := fake.called(authAPIPath); got != tt.wantAuthCalled {
				t.Errorf("auth API called = %v, want %v", got, tt.wantAuthCalled)
			}
		})
	}
}

func TestDuo_Verification_IndeterminateErrorExplainsCodes(t *testing.T) {
	tests := []struct {
		name           string
		admin          duoResponse
		auth           duoResponse
		wantContains   []string
		wantNoContains []string
	}{
		{
			name:         "missing Admin API permission is called out",
			admin:        duoError(40301),
			auth:         duoError(40301),
			wantContains: []string{"HTTP 403 (code 40301)", `"Grant read information"`},
		},
		{
			name:           "other integration types get no permission hint",
			admin:          duoError(40102),
			auth:           duoError(40301),
			wantContains:   []string{"HTTP 401 (code 40102)", "HTTP 403 (code 40301)"},
			wantNoContains: []string{"Grant read information"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := newFakeDuoClient(t, tt.admin, tt.auth)
			s := Scanner{client: client}

			results, err := s.FromData(context.Background(), true, testData())
			if err != nil || len(results) != 1 {
				t.Fatalf("expected 1 result, got %d (err %v)", len(results), err)
			}
			vErr := results[0].VerificationError()
			if vErr == nil {
				t.Fatal("expected a verification error")
			}
			for _, s := range tt.wantContains {
				if !strings.Contains(vErr.Error(), s) {
					t.Errorf("verification error %q does not contain %q", vErr, s)
				}
			}
			for _, s := range tt.wantNoContains {
				if strings.Contains(vErr.Error(), s) {
					t.Errorf("verification error %q must not contain %q", vErr, s)
				}
			}
		})
	}
}

func TestDuo_Verification_RequestShape(t *testing.T) {
	client, fake := newFakeDuoClient(t, duoError(40102), okReply)
	s := Scanner{client: client}

	if _, err := s.FromData(context.Background(), true, testData()); err != nil {
		t.Fatalf("FromData error: %v", err)
	}

	for _, path := range []string{adminAPIPath, authAPIPath} {
		req := fake.requests[path]
		if req == nil {
			t.Fatalf("no request sent to %s", path)
		}
		if req.Method != http.MethodGet {
			t.Errorf("%s method = %s, want GET", path, req.Method)
		}
		if req.URL.Host != testHost {
			t.Errorf("%s host = %s, want %s", path, req.URL.Host, testHost)
		}
		if req.Header.Get("Date") == "" {
			t.Errorf("%s request has no Date header", path)
		}
		encoded, found := strings.CutPrefix(req.Header.Get("Authorization"), "Basic ")
		if !found {
			t.Fatalf("%s Authorization header is not Basic auth", path)
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("%s Authorization header is not base64: %v", path, err)
		}
		if !strings.HasPrefix(string(decoded), testIKey+":") {
			t.Errorf("%s Authorization user is not the integration key", path)
		}
		if strings.Contains(string(decoded), testSKey) {
			t.Errorf("%s Authorization header leaks the secret key", path)
		}
	}
}

func TestDuo_Verification_ErrorNeverContainsSecret(t *testing.T) {
	client, _ := newFakeDuoClient(t, duoError(40301), duoError(40301))
	s := Scanner{client: client}

	results, err := s.FromData(context.Background(), true, testData())
	if err != nil || len(results) != 1 {
		t.Fatalf("expected 1 result, got %d (err %v)", len(results), err)
	}
	vErr := results[0].VerificationError()
	if vErr == nil {
		t.Fatal("expected a verification error")
	}
	if strings.Contains(vErr.Error(), testSKey) {
		t.Errorf("verification error leaks the secret key: %s", vErr)
	}
}

func TestDuo_Verification_SkippedWhenVerifyIsFalse(t *testing.T) {
	client, fake := newFakeDuoClient(t, okReply, okReply)
	s := Scanner{client: client}

	results, err := s.FromData(context.Background(), false, testData())
	if err != nil || len(results) != 1 {
		t.Fatalf("expected 1 result, got %d (err %v)", len(results), err)
	}
	if fake.called(adminAPIPath) || fake.called(authAPIPath) {
		t.Error("verify=false must not call the Duo API")
	}
	if results[0].Verified {
		t.Error("unverified scan must not mark the key verified")
	}
	if got := results[0].ExtraData["application"]; got != adminApplication {
		t.Errorf("ExtraData application = %q, want %q", got, adminApplication)
	}
}
