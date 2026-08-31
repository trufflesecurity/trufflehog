package humioingesttoken

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
	validPattern   = "0de23adb-2093-4866-8daa-f11fe12149dd"
	invalidPattern = "0de23adb?2093-4866-8daa-f11fe12149dd"
)

func TestHumioIngestToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - humio keyword",
			input: fmt.Sprintf("humio_ingest_token = '%s'", validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - logscale keyword",
			input: fmt.Sprintf("logscale_ingest_token = '%s'", validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("humio token = '%s' | '%s'", validPattern, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("humio keyword is not close to the real key in the data\n = '%s'", validPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("humio = '%s'", invalidPattern),
			want:  []string{},
		},
		{
			name:  "low entropy placeholder UUID rejected",
			input: "humio_token = '11111111-1111-1111-1111-111111111111'",
			want:  []string{},
		},
		{
			name:  "low entropy all-zeros UUID rejected",
			input: "humio_token = '00000000-0000-0000-0000-000000000000'",
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

// Exercise the verification logic against a mock HEC server. Each HTTP status
// code maps to a specific verified/error outcome — 403 and 422 both count as
// verified because they indicate the server recognized the token.
func TestHumioIngestToken_Verification(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		wantVerified bool
		wantErr      bool
	}{
		{"200 - valid token", http.StatusOK, true, false},
		{"401 - unknown token", http.StatusUnauthorized, false, false},
		{"403 - recognized but blocked", http.StatusForbidden, true, false},
		{"422 - deleted repo", http.StatusUnprocessableEntity, true, false},
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

			input := fmt.Sprintf("humio_token = '%s'", validPattern)
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

// Verify that a clean 401 from the wrong region does not erase a transient
// error from an earlier endpoint. The verification error should survive so
// consumers know the result is uncertain, not definitively "not valid."
func TestHumioIngestToken_Verification_ErrorPreservedAcross401(t *testing.T) {
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

	input := fmt.Sprintf("humio_token = '%s'", validPattern)
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

// Bare UUIDs without Humio/LogScale context must not reach this detector at
// all — the Aho-Corasick pre-filter should reject the chunk.
func TestHumioIngestToken_NoKeywordMatch(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	input := fmt.Sprintf("some_generic_token = '%s'", validPattern)
	matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(input))
	if len(matchedDetectors) != 0 {
		t.Errorf("expected no keyword match for input without humio/logscale context, got %d", len(matchedDetectors))
	}
}
