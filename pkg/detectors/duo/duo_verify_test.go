package duo

import (
	"context"
	"encoding/base64"
	"errors"
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

// Response bodies as returned by Duo.
const (
	bodyOK               = `{"stat": "OK", "response": {}}`
	bodyInvalidSignature = `{"code": 40103, "message": "Invalid signature in request credentials", "stat": "FAIL"}`
	bodyWrongIntegration = `{"code": 40301, "message": "Access forbidden", "message_detail": "Wrong integration type for this API.", "stat": "FAIL"}`
)

var errNetwork = errors.New("network unreachable")

// duoResponse is the fake answer for one API path. A nil value means the
// transport fails for that path.
type duoResponse *int

func status(code int) duoResponse { return &code }

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

				resp, ok := responses[req.URL.Path]
				if !ok {
					t.Errorf("unexpected request path %s", req.URL.Path)
					return nil, errNetwork
				}
				if resp == nil {
					return nil, errNetwork
				}
				body := bodyOK
				switch *resp {
				case http.StatusUnauthorized:
					body = bodyInvalidSignature
				case http.StatusForbidden:
					body = bodyWrongIntegration
				}
				return &http.Response{
					Request:    req,
					StatusCode: *resp,
					Body:       io.NopCloser(strings.NewReader(body)),
				}, nil
			},
		},
	}
	return client, fake
}

func (f *fakeDuo) called(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.requests[path]
	return ok
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
		{
			name:  "admin 200 verifies an Admin API key",
			admin: status(200), auth: status(403),
			wantVerified: true, wantApplication: adminApplication,
		},
		{
			name:  "admin 401, auth 200 verifies an Auth API key",
			admin: status(401), auth: status(200),
			wantVerified: true, wantApplication: authApplication, wantAuthCalled: true,
		},
		{
			name:  "admin 403, auth 200 verifies an Auth API key",
			admin: status(403), auth: status(200),
			wantVerified: true, wantApplication: authApplication, wantAuthCalled: true,
		},
		{
			name:  "admin 401, auth 403 is invalid",
			admin: status(401), auth: status(403),
			wantApplication: adminApplication, wantAuthCalled: true,
		},
		{
			name:  "admin 401, auth 401 is invalid",
			admin: status(401), auth: status(401),
			wantApplication: adminApplication, wantAuthCalled: true,
		},
		{
			name:  "admin 403, auth 401 is invalid",
			admin: status(403), auth: status(401),
			wantApplication: adminApplication, wantAuthCalled: true,
		},
		{
			name:  "admin network error, auth 401 is invalid",
			admin: nil, auth: status(401),
			wantApplication: adminApplication, wantAuthCalled: true,
		},
		{
			name:  "admin 401, auth network error is indeterminate",
			admin: status(401), auth: nil,
			wantApplication: adminApplication, wantErr: true, wantAuthCalled: true,
		},
		{
			name:  "admin 401, auth 500 is indeterminate",
			admin: status(401), auth: status(500),
			wantApplication: adminApplication, wantErr: true, wantAuthCalled: true,
		},
		{
			name:  "admin 403, auth 403 is indeterminate",
			admin: status(403), auth: status(403),
			wantApplication: adminApplication, wantErr: true, wantAuthCalled: true,
		},
		{
			name:  "admin 500 is indeterminate",
			admin: status(500), auth: status(403),
			wantApplication: adminApplication, wantErr: true, wantAuthCalled: true,
		},
		{
			name:  "admin network error, auth 403 is indeterminate",
			admin: nil, auth: status(403),
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

func TestDuo_Verification_RequestShape(t *testing.T) {
	client, fake := newFakeDuoClient(t, status(401), status(200))
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
		encoded, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Basic ")
		if !ok {
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
	client, _ := newFakeDuoClient(t, status(403), status(403))
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
	client, fake := newFakeDuoClient(t, status(200), status(200))
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
