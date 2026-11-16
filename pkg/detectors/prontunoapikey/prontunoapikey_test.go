package prontunoapikey

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// Synthetic keys in the exact shape Prontuno issues, with valid checksums.
// Not real credentials.
const (
	validKey   = "pno_sk_01kxh2fjk3e00b2n8r6ysx4d7k_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef2d7c6e57"
	validKeyID = "key_01kxh2fjk3e00b2n8r6ysx4d7k"
)

func TestProntunoApiKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - env file",
			input: `PRONTUNO_API_KEY=` + validKey,
			want:  []string{validKey},
		},
		{
			name:  "valid pattern - authorization header",
			input: `curl https://api.prontuno.net/v1/emails -H "Authorization: Bearer ` + validKey + `"`,
			want:  []string{validKey},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: `key = "` + validKey + `" | "` + validKey + `"`,
			want:  []string{validKey},
		},
		{
			name:  "invalid pattern - checksum mismatch",
			input: `PRONTUNO_API_KEY=pno_sk_01kxh2fjk3e00b2n8r6ysx4d7k_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef2d7c6e58`,
			want:  nil,
		},
		{
			name:  "invalid pattern - key ID above the 128-bit range",
			input: `PRONTUNO_API_KEY=pno_sk_81kxh2fjk3e00b2n8r6ysx4d7k_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef2d7c6e57`,
			want:  nil,
		},
		{
			name:  "invalid pattern - uppercase secret",
			input: `PRONTUNO_API_KEY=pno_sk_01kxh2fjk3e00b2n8r6ysx4d7k_0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef2d7c6e57`,
			want:  nil,
		},
		{
			name:  "invalid pattern - too short",
			input: `PRONTUNO_API_KEY=` + validKey[:len(validKey)-1],
			want:  nil,
		},
		{
			name:  "invalid pattern - too long",
			input: `PRONTUNO_API_KEY=` + validKey + `a`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, received %d", len(test.want), len(results))
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				actual[string(r.Raw)] = struct{}{}
				if r.SecretParts["key"] != string(r.Raw) {
					t.Errorf("SecretParts[key] = %q, want %q", r.SecretParts["key"], r.Raw)
				}
				if r.ExtraData["key_id"] != validKeyID {
					t.Errorf("ExtraData[key_id] = %q, want %q", r.ExtraData["key_id"], validKeyID)
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

// usageServer replies with status and body to every request and counts
// them. It fails the test unless each request is GET /v1/usage carrying
// validKey as a bearer token.
func usageServer(t *testing.T, status int, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/v1/usage" {
			t.Errorf("unexpected request %s %s, want GET /v1/usage", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+validKey {
			t.Errorf("Authorization = %q, want the bearer key", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	return ts, &hits
}

func TestProntunoApiKey_Verification(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		wantVerified bool
		wantErr      bool
		wantAccess   string
	}{
		{
			name:         "200 verifies an account-wide key",
			status:       http.StatusOK,
			body:         `{"data":{}}`,
			wantVerified: true,
			wantAccess:   "account-wide (Management or MCP key)",
		},
		{
			name:         "403 insufficient_scope verifies a restricted key",
			status:       http.StatusForbidden,
			body:         `{"error":{"code":"insufficient_scope","message":"API key lacks the required scope"}}`,
			wantVerified: true,
			wantAccess:   "restricted (Sending or Receiving key)",
		},
		{
			name:   "401 determinately invalid",
			status: http.StatusUnauthorized,
			body:   `{"error":{"code":"invalid_api_key","message":"Invalid API key"}}`,
		},
		{
			name:    "403 with another error code is indeterminate",
			status:  http.StatusForbidden,
			body:    `{"error":{"code":"missing_edge_key","message":"Missing edge key"}}`,
			wantErr: true,
		},
		{
			name:    "403 without a JSON body is indeterminate",
			status:  http.StatusForbidden,
			body:    `<html>Access Denied</html>`,
			wantErr: true,
		},
		{name: "429 indeterminate", status: http.StatusTooManyRequests, wantErr: true},
		{name: "500 indeterminate", status: http.StatusInternalServerError, wantErr: true},
		{name: "503 indeterminate", status: http.StatusServiceUnavailable, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts, hits := usageServer(t, test.status, test.body)
			defer ts.Close()

			d := Scanner{client: ts.Client(), verifyURL: ts.URL + "/v1/usage"}
			results, err := d.FromData(context.Background(), true, []byte("PRONTUNO_API_KEY="+validKey))
			if err != nil {
				t.Fatalf("FromData: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			r := results[0]
			if r.Verified != test.wantVerified {
				t.Errorf("Verified = %v, want %v", r.Verified, test.wantVerified)
			}
			if (r.VerificationError() != nil) != test.wantErr {
				t.Errorf("VerificationError = %v, wantErr = %v", r.VerificationError(), test.wantErr)
			}
			if got := r.ExtraData["access"]; got != test.wantAccess {
				t.Errorf("ExtraData[access] = %q, want %q", got, test.wantAccess)
			}
			if got := hits.Load(); got != 1 {
				t.Errorf("requests = %d, want 1", got)
			}
		})
	}
}

func TestProntunoApiKey_NetworkErrorIsIndeterminate(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	verifyURL := ts.URL + "/v1/usage"
	ts.Close()

	d := Scanner{client: ts.Client(), verifyURL: verifyURL}
	results, err := d.FromData(context.Background(), true, []byte("PRONTUNO_API_KEY="+validKey))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(results) != 1 || results[0].Verified || results[0].VerificationError() == nil {
		t.Fatalf("want one unverified result with a verification error, got %+v", results)
	}
}

func TestProntunoApiKey_ChecksumFailureIsNotVerified(t *testing.T) {
	ts, hits := usageServer(t, http.StatusOK, `{}`)
	defer ts.Close()

	d := Scanner{client: ts.Client(), verifyURL: ts.URL + "/v1/usage"}
	input := "PRONTUNO_API_KEY=" + validKey[:len(validKey)-1] + "0"
	results, err := d.FromData(context.Background(), true, []byte(input))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(results) != 0 || hits.Load() != 0 {
		t.Fatalf("want no results and no requests, got %d results and %d requests", len(results), hits.Load())
	}
}
