package composio

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Real production envelopes captured 2026-09-17 with never-minted keys; the
// request_id field is dropped and the masked key placeholder is synthetic.
const (
	bodyProjectInvalid   = `{"error":{"message":"Invalid API key: ak_**ESjq","code":801,"slug":"APIKey_InvalidAPIKey","status":401}}`
	bodyProjectExpired   = `{"error":{"message":"API key has expired","code":811,"slug":"APIKey_APIKeyExpired","status":401}}`
	bodyOrgInvalid       = `{"error":{"message":"Invalid x-org-api-key. Please check you are using a valid API key.","code":10401,"slug":"HTTP_Unauthorized","status":401}}`
	bodyUserInvalid      = `{"error":{"message":"Invalid or revoked user API key","code":2113,"slug":"UserApiKey_Unauthorized","status":401}}`
	bodyNoAuth           = `{"error":{"message":"No API key provided","code":906,"slug":"Auth_NoAuthProvided","status":401}}`
	bodyIPAllowlist      = `{"error":{"message":"This request comes from IP address 203.0.113.9, which is not in this API key’s IP allowlist. Requests using this key are only accepted from explicitly allowlisted IP addresses.","code":902,"slug":"Auth_Unauthorized","status":401}}`
	bodyAccessDenied     = `{"error":{"message":"Access denied","code":902,"slug":"Auth_Unauthorized","status":401}}`
	bodyOrgAccessDenied  = `{"error":{"message":"Access denied","code":10401,"slug":"HTTP_Unauthorized","status":401}}`
	bodyNoPermission     = `{"error":{"message":"This API key does not have read access to toolkits","code":812,"slug":"APIKey_InsufficientPermissions","status":403}}`
	bodyForbiddenUnknown = `{"error":{"message":"Organization is suspended","code":2206,"slug":"Organization_InsufficientPermissions","status":403}}`
	bodyHTMLChallenge    = `<!DOCTYPE html><html><head><title>Just a moment...</title></head></html>`
)

type capturedRequest struct {
	method  string
	path    string
	headers http.Header
}

// newVerifyServer answers every request with the given status and body and
// records the last request it saw.
func newVerifyServer(t *testing.T, status int, body string) (*httptest.Server, *capturedRequest, *int32) {
	t.Helper()
	captured := &capturedRequest{}
	var calls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		captured.method = r.Method
		captured.path = r.URL.RequestURI()
		captured.headers = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return ts, captured, &calls
}

func scannerFor(ts *httptest.Server) Scanner {
	s := Scanner{}
	s.SetCloudEndpoint(ts.URL)
	s.UseCloudEndpoint(true)
	return s
}

func TestComposio_Verification_RequestShape(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		wantPath   string
		wantHeader string
	}{
		{name: "project key", key: projectKey, wantPath: "/api/v3/toolkits/categories", wantHeader: "x-api-key"},
		{name: "org key", key: orgKey, wantPath: "/api/v3/org/owner/project/list", wantHeader: "x-org-api-key"},
		{name: "user key", key: userKey, wantPath: "/api/v3/org/list?limit=1", wantHeader: "x-user-api-key"},
	}

	keyHeaders := []string{"x-api-key", "x-org-api-key", "x-user-api-key", "Authorization"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, captured, _ := newVerifyServer(t, http.StatusOK, `{}`)
			s := scannerFor(ts)

			results, err := s.FromData(context.Background(), true, []byte("key="+tt.key))
			if err != nil {
				t.Fatalf("FromData error: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			if captured.method != http.MethodGet {
				t.Errorf("method = %s, want GET", captured.method)
			}
			if captured.path != tt.wantPath {
				t.Errorf("path = %s, want %s", captured.path, tt.wantPath)
			}
			if got := captured.headers.Get(tt.wantHeader); got != tt.key {
				t.Errorf("header %s = %q, want the key", tt.wantHeader, got)
			}
			for _, h := range keyHeaders {
				if h != tt.wantHeader && captured.headers.Get(h) != "" {
					t.Errorf("header %s must not be sent for a %s key", h, tt.name)
				}
			}
			if !results[0].Verified {
				t.Error("200 must verify the key")
			}
			if results[0].VerificationError() != nil {
				t.Errorf("unexpected verification error: %v", results[0].VerificationError())
			}
			if got := results[0].ExtraData["endpoint"]; got != ts.URL {
				t.Errorf("ExtraData endpoint = %q, want %q", got, ts.URL)
			}
		})
	}
}

func TestComposio_Verification_Outcomes(t *testing.T) {
	tests := []struct {
		name            string
		key             string
		status          int
		body            string
		wantVerified    bool
		wantErr         bool
		wantRestriction string
	}{
		// Definitive rejections: the key hash matched no live row.
		{name: "project: unknown or revoked", key: projectKey, status: 401, body: bodyProjectInvalid},
		{name: "project: expired", key: projectKey, status: 401, body: bodyProjectExpired},
		{name: "org: unknown or revoked", key: orgKey, status: 401, body: bodyOrgInvalid},
		{name: "user: unknown, revoked or expired", key: userKey, status: 401, body: bodyUserInvalid},

		// Live keys the route would not serve.
		{name: "project: IP allowlist denial is a live key", key: projectKey, status: 401, body: bodyIPAllowlist, wantVerified: true, wantRestriction: "ip_allowlist"},
		{name: "project: scoped key without permission is a live key", key: projectKey, status: 403, body: bodyNoPermission, wantVerified: true, wantRestriction: "insufficient_permissions"},

		// The API did not judge the key; never guess.
		{name: "project: banned scanner IP", key: projectKey, status: 401, body: bodyAccessDenied, wantErr: true},
		{name: "org: banned scanner IP", key: orgKey, status: 401, body: bodyOrgAccessDenied, wantErr: true},
		{name: "user: membership could not be resolved", key: userKey, status: 401, body: bodyAccessDenied, wantErr: true},
		{name: "header not recognised", key: projectKey, status: 401, body: bodyNoAuth, wantErr: true},
		{name: "401 without a Composio envelope", key: projectKey, status: 401, body: bodyHTMLChallenge, wantErr: true},
		{name: "org: 403 after the key resolved is a live key", key: orgKey, status: 403, body: bodyForbiddenUnknown, wantVerified: true, wantRestriction: "Organization_InsufficientPermissions"},
		{name: "403 without a Composio envelope", key: projectKey, status: 403, body: bodyHTMLChallenge, wantErr: true},
		{name: "rate limited", key: projectKey, status: 429, body: `{"error":{"message":"Too many requests","code":429,"slug":"RateLimit_Exceeded","status":429}}`, wantErr: true},
		{name: "server error", key: projectKey, status: 500, body: ``, wantErr: true},
		{name: "redirect is not a verdict", key: projectKey, status: 302, body: ``, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, _, _ := newVerifyServer(t, tt.status, tt.body)
			s := scannerFor(ts)

			results, err := s.FromData(context.Background(), true, []byte("key="+tt.key))
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
			if got := r.ExtraData["restriction"]; got != tt.wantRestriction {
				t.Errorf("ExtraData restriction = %q, want %q", got, tt.wantRestriction)
			}
			if r.ExtraData["key_type"] == "" {
				t.Error("key_type must survive verification")
			}
		})
	}
}

func TestComposio_Verification_ErrorNeverContainsKey(t *testing.T) {
	ts, _, _ := newVerifyServer(t, http.StatusUnauthorized, bodyAccessDenied)
	s := scannerFor(ts)

	results, err := s.FromData(context.Background(), true, []byte("key="+projectKey))
	if err != nil || len(results) != 1 {
		t.Fatalf("expected 1 result, got %d (err %v)", len(results), err)
	}
	vErr := results[0].VerificationError()
	if vErr == nil {
		t.Fatal("expected a verification error")
	}
	if msg := vErr.Error(); strings.Contains(msg, projectKey) {
		t.Errorf("verification error leaks the key: %s", msg)
	}
}

func TestComposio_Verification_SkippedWhenVerifyIsFalse(t *testing.T) {
	ts, _, calls := newVerifyServer(t, http.StatusOK, `{}`)
	s := scannerFor(ts)

	results, err := s.FromData(context.Background(), false, []byte("key="+projectKey))
	if err != nil || len(results) != 1 {
		t.Fatalf("expected 1 result, got %d (err %v)", len(results), err)
	}
	if *calls != 0 {
		t.Errorf("verify=false must not call the API, saw %d requests", *calls)
	}
	if results[0].Verified {
		t.Error("unverified scan must not mark the key verified")
	}
}

func TestComposio_Verification_NoEndpointsNoRequest(t *testing.T) {
	ts, _, calls := newVerifyServer(t, http.StatusOK, `{}`)
	s := Scanner{}
	s.SetCloudEndpoint(ts.URL)
	s.UseCloudEndpoint(false)

	results, err := s.FromData(context.Background(), true, []byte("key="+projectKey))
	if err != nil || len(results) != 1 {
		t.Fatalf("expected 1 result, got %d (err %v)", len(results), err)
	}
	if *calls != 0 {
		t.Errorf("no configured endpoints must mean no request, saw %d", *calls)
	}
	if results[0].Verified || results[0].VerificationError() != nil {
		t.Error("with no endpoints the result stays unverified and error-free")
	}
}

func TestComposio_Verification_LaterEndpointClearsEarlierError(t *testing.T) {
	ts500, _, _ := newVerifyServer(t, http.StatusInternalServerError, ``)
	ts200, _, _ := newVerifyServer(t, http.StatusOK, `{}`)
	s := Scanner{}
	if err := s.SetConfiguredEndpoints(ts500.URL, ts200.URL); err != nil {
		t.Fatal(err)
	}

	results, err := s.FromData(context.Background(), true, []byte("key="+projectKey))
	if err != nil || len(results) != 1 {
		t.Fatalf("expected 1 result, got %d (err %v)", len(results), err)
	}
	if !results[0].Verified {
		t.Error("second endpoint answered 200, key must be verified")
	}
	if results[0].VerificationError() != nil {
		t.Errorf("earlier 500 must be cleared by the later 200: %v", results[0].VerificationError())
	}
	if got := results[0].ExtraData["endpoint"]; got != ts200.URL {
		t.Errorf("endpoint = %q, want %q", got, ts200.URL)
	}
}

func TestComposio_Verification_DeadOnOneEndpointKeepsEarlierError(t *testing.T) {
	ts500, _, _ := newVerifyServer(t, http.StatusInternalServerError, ``)
	tsDead, _, _ := newVerifyServer(t, http.StatusUnauthorized, bodyProjectInvalid)
	s := Scanner{}
	if err := s.SetConfiguredEndpoints(ts500.URL, tsDead.URL); err != nil {
		t.Fatal(err)
	}

	results, err := s.FromData(context.Background(), true, []byte("key="+projectKey))
	if err != nil || len(results) != 1 {
		t.Fatalf("expected 1 result, got %d (err %v)", len(results), err)
	}
	if results[0].Verified {
		t.Error("a clean 401 must not verify")
	}
	if results[0].VerificationError() == nil {
		t.Error("a clean 401 from one endpoint must not erase the 500 from another")
	}
}

func TestComposio_CloudEndpoint(t *testing.T) {
	if got := (Scanner{}).CloudEndpoint(); got != "https://backend.composio.dev" {
		t.Errorf("CloudEndpoint() = %q", got)
	}
}

func TestComposio_RotationGuideResolves(t *testing.T) {
	results, err := Scanner{}.FromData(context.Background(), false, []byte(projectKey))
	if err != nil || len(results) != 1 {
		t.Fatalf("expected 1 result, got %d (err %v)", len(results), err)
	}
	if got := results[0].ExtraData["rotation_guide"]; got != "https://docs.composio.dev/reference/api-reference/api-keys/postApiKeyRevocation" {
		t.Errorf("rotation_guide = %q", got)
	}
}
