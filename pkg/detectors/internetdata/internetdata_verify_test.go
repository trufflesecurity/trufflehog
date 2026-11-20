package internetdata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Production answers captured 2026-11-19; the 200 body is cut to the fields the
// detector reads.
const (
	bodyLive        = `{"plan":{"key":"free","name":"Unlimited","tier":"free"}}`
	bodyInvalid     = `{"error":"invalid API key"}`
	bodyRevoked     = `{"error":"API key revoked"}`
	bodyExpired     = `{"error":"API key expired"}`
	bodyKeyRequired = `{"error":"an API key is required"}`
	bodyAllowlist   = `{"error":"source address not allowed for this API key"}`
	bodyUnavailable = `{"error":"usage is temporarily unavailable"}`
	bodyHTML        = `<!DOCTYPE html><html><head><title>Just a moment...</title></head></html>`
)

type capturedRequest struct {
	method  string
	path    string
	headers http.Header
}

// newVerifyServer answers every request with the given status and body and
// records the last request it saw.
func newVerifyServer(t *testing.T, status int, body string) (*httptest.Server, *capturedRequest) {
	t.Helper()
	captured := &capturedRequest{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.RequestURI()
		captured.headers = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return ts, captured
}

func scannerFor(ts *httptest.Server) Scanner {
	s := Scanner{}
	s.SetCloudEndpoint(ts.URL)
	s.UseCloudEndpoint(true)
	return s
}

func TestInternetData_Verification_RequestShape(t *testing.T) {
	ts, captured := newVerifyServer(t, http.StatusOK, bodyLive)
	s := scannerFor(ts)

	results, err := s.FromData(context.Background(), true, []byte("key="+validKey))
	if err != nil {
		t.Fatalf("FromData error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if captured.method != http.MethodGet {
		t.Errorf("method = %s, want GET", captured.method)
	}
	if captured.path != "/api/v1/entitlement" {
		t.Errorf("path = %s, want /api/v1/entitlement", captured.path)
	}
	if got := captured.headers.Get("X-Api-Key"); got != validKey {
		t.Errorf("X-Api-Key = %q, want the key", got)
	}
	if !results[0].Verified {
		t.Error("200 must verify the key")
	}
	if results[0].VerificationError() != nil {
		t.Errorf("unexpected verification error: %v", results[0].VerificationError())
	}
	if got := results[0].ExtraData["plan"]; got != "Unlimited" {
		t.Errorf("ExtraData plan = %q, want Unlimited", got)
	}
	if got := results[0].ExtraData["endpoint"]; got != ts.URL {
		t.Errorf("ExtraData endpoint = %q, want %q", got, ts.URL)
	}
}

func TestInternetData_Verification_Outcomes(t *testing.T) {
	tests := []struct {
		name            string
		status          int
		body            string
		wantVerified    bool
		wantErr         bool
		wantRestriction string
	}{
		{name: "live", status: http.StatusOK, body: bodyLive, wantVerified: true},
		{name: "live, unexpected body", status: http.StatusOK, body: `{}`, wantVerified: true},
		{name: "invalid", status: http.StatusUnauthorized, body: bodyInvalid},
		{name: "revoked", status: http.StatusUnauthorized, body: bodyRevoked},
		{name: "expired", status: http.StatusUnauthorized, body: bodyExpired},
		{name: "live but limited to allowed addresses", status: http.StatusForbidden, body: bodyAllowlist, wantVerified: true, wantRestriction: "ip_allowlist"},
		{name: "key header stripped on the way", status: http.StatusUnauthorized, body: bodyKeyRequired, wantErr: true},
		{name: "401 without the envelope", status: http.StatusUnauthorized, body: bodyHTML, wantErr: true},
		{name: "usage unavailable", status: http.StatusServiceUnavailable, body: bodyUnavailable, wantErr: true},
		{name: "rate limited", status: http.StatusTooManyRequests, body: `{"error":"rate limited"}`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, _ := newVerifyServer(t, tt.status, tt.body)
			s := scannerFor(ts)

			results, err := s.FromData(context.Background(), true, []byte(validKey))
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
			if gotErr := r.VerificationError() != nil; gotErr != tt.wantErr {
				t.Errorf("verification error = %v, want error: %v", r.VerificationError(), tt.wantErr)
			}
			if got := r.ExtraData["restriction"]; got != tt.wantRestriction {
				t.Errorf("restriction = %q, want %q", got, tt.wantRestriction)
			}
		})
	}
}
