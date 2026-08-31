package humioapitoken

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// 32-char prefix + tilde + 44-char suffix
	validPattern32 = "pHUw1oLASALFmt2ppNvwCR0Meo2nHQ15~ECViF0Ce95uIqFGSSatjKWX71EOzvkpVGSuc3zGYqJgR"
	// 24-char prefix + tilde + 44-char suffix
	validPattern24 = "abcDefGhiJklMnoPqrStUvWx~ECViF0Ce95uIqFGSSatjKWX71EOzvkpVGSuc3zGYqJgR"
)

func TestHumioAPIToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - humio keyword, 32-char prefix",
			input: fmt.Sprintf("humio_api_token = '%s'", validPattern32),
			want:  []string{validPattern32},
		},
		{
			name:  "valid pattern - humio keyword, 24-char prefix",
			input: fmt.Sprintf("humio_api_token = '%s'", validPattern24),
			want:  []string{validPattern24},
		},
		{
			name:  "valid pattern - logscale keyword",
			input: fmt.Sprintf("logscale_api_token = '%s'", validPattern32),
			want:  []string{validPattern32},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("humio token = '%s' | '%s'", validPattern32, validPattern32),
			want:  []string{validPattern32},
		},
		{
			name:  "valid pattern - token far from keyword",
			input: fmt.Sprintf("humio config loaded\n\n\napi_token = '%s'", validPattern32),
			want:  []string{validPattern32},
		},
		{
			name:  "invalid pattern - tilde present but suffix too short",
			input: "humio_token = 'pHUw1oLASALFmt2ppNvwCR0Meo2nHQ15~ECViF0Ce95uIqFGSS'",
			want:  []string{},
		},
		{
			name:  "invalid pattern - tilde present but segments too short",
			input: "humio_token = 'abc~def'",
			want:  []string{},
		},
		{
			name:  "invalid pattern - wrong prefix length (28 chars)",
			input: "humio_token = 'abcDefGhiJklMnoPqrStUvWxYzAb~ECViF0Ce95uIqFGSSatjKWX71EOzvkpVGSuc3zGYqJgR'",
			want:  []string{},
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
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
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

// Exercise the verification logic against a mock health-json server. Each
// HTTP status code maps to a specific verified/error outcome — 403 counts as
// verified because the server recognized the token (just blocked by IP filter).
func TestHumioAPIToken_Verification(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		wantVerified bool
		wantErr      bool
	}{
		{"200 - valid token", http.StatusOK, true, false},
		{"401 - unknown token", http.StatusUnauthorized, false, false},
		{"403 - recognized but blocked", http.StatusForbidden, true, false},
		{"500 - server error", http.StatusInternalServerError, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer ts.Close()

			s := Scanner{}
			s.SetCloudEndpoint(ts.URL)
			s.UseCloudEndpoint(true)

			input := fmt.Sprintf("humio_token = '%s'", validPattern32)
			results, err := s.FromData(context.Background(), true, []byte(input))
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
				t.Error("expected verification error, got nil")
			}
			if !tt.wantErr && r.VerificationError() != nil {
				t.Errorf("unexpected verification error: %v", r.VerificationError())
			}
		})
	}
}

// Verify that a successful verification on a later endpoint clears any
// error from an earlier failed attempt (e.g. first endpoint returns 500,
// second returns 200).
func TestHumioAPIToken_Verification_StaleErrorCleared(t *testing.T) {
	callCount := 0
	ts500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts500.Close()

	ts200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer ts200.Close()

	s := Scanner{}
	_ = s.SetConfiguredEndpoints(ts500.URL, ts200.URL)

	input := fmt.Sprintf("humio_token = '%s'", validPattern32)
	results, err := s.FromData(context.Background(), true, []byte(input))
	if err != nil {
		t.Fatalf("FromData error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if !r.Verified {
		t.Error("expected Verified = true after second endpoint succeeded")
	}
	if r.VerificationError() != nil {
		t.Errorf("stale verification error not cleared: %v", r.VerificationError())
	}
}

// Verify that a clean 401 from the wrong region does not erase a transient
// error from an earlier endpoint. The verification error should survive so
// consumers know the result is uncertain, not definitively "not valid."
func TestHumioAPIToken_Verification_ErrorPreservedAcross401(t *testing.T) {
	ts500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts500.Close()

	ts401 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts401.Close()

	s := Scanner{}
	_ = s.SetConfiguredEndpoints(ts500.URL, ts401.URL)

	input := fmt.Sprintf("humio_token = '%s'", validPattern32)
	results, err := s.FromData(context.Background(), true, []byte(input))
	if err != nil {
		t.Fatalf("FromData error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Verified {
		t.Error("expected Verified = false")
	}
	if r.VerificationError() == nil {
		t.Error("expected verification error to be preserved after 401 from another endpoint, got nil")
	}
}

func TestHumioAPIToken_TokenType(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"24-char prefix is Personal API Token", validPattern24, "Personal API Token"},
		{"32-char prefix is Repository API Token", validPattern32, "Repository API Token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := humioTokenType(tt.token)
			if got != tt.want {
				t.Errorf("humioTokenType() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Data without humio/logscale context must not reach this detector — the
// Aho-Corasick pre-filter should reject the chunk.
func TestHumioAPIToken_NoKeywordMatch(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	input := fmt.Sprintf("some_generic_token = '%s'", validPattern32)
	matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(input))
	if len(matchedDetectors) != 0 {
		t.Errorf("expected no keyword match for input without humio/logscale context, got %d", len(matchedDetectors))
	}
}
