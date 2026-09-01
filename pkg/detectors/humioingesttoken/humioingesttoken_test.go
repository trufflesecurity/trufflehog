package humioingesttoken

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var validPattern = "0de23adb-2093-4866-8daa-f11fe12149dd"

func TestHumioIngestToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - env file with humio prefix",
			input: `
				# Log shipper credentials
				HUMIO_INGEST_TOKEN=0de23adb-2093-4866-8daa-f11fe12149dd
				HUMIO_BASE_URL=https://cloud.us.humio.com
				LOG_LEVEL=info`,
			want: []string{validPattern},
		},
		{
			name: "valid pattern - logscale keyword in docker compose",
			input: `
				services:
				  log-shipper:
				    image: fluent/fluent-bit:latest
				    environment:
				      - LOGSCALE_INGEST_TOKEN=0de23adb-2093-4866-8daa-f11fe12149dd
				      - LOGSCALE_HOST=https://cloud.us.humio.com
				    restart: always`,
			want: []string{validPattern},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("humio token = '%s' | '%s'", validPattern, validPattern),
			want:  []string{validPattern},
		},
		{
			name: "keyword too far from token - PrefixRegex rejects",
			input: `
				# humio keyword is not close to the real key in the data
				# lots of intervening text that pushes the token out of PrefixRegex range
				some_other_setting = "foo"
				ingest_token = "0de23adb-2093-4866-8daa-f11fe12149dd"`,
			want: []string{},
		},
		{
			name: "invalid pattern - question mark instead of hyphen",
			input: `
				[humio]
				ingest_token = "0de23adb?2093-4866-8daa-f11fe12149dd"`,
			want: []string{},
		},
		{
			name: "low entropy placeholder UUID rejected",
			input: `
				# humio default config - replace with real token
				HUMIO_INGEST_TOKEN=11111111-1111-1111-1111-111111111111`,
			want: []string{},
		},
		{
			name: "low entropy all-zeros UUID rejected",
			input: `
				# humio placeholder
				ingest_token: "00000000-0000-0000-0000-000000000000"`,
			want: []string{},
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
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
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

// Exercise the verification logic against a mock structured-ingest server.
// The detector sends intentionally invalid JSON; the status code alone
// determines the outcome per the LogScale Ingest API response table.
func TestHumioIngestToken_Verification(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		wantVerified bool
		wantErr      bool
	}{
		{"200 - token valid, payload accepted", http.StatusOK, true, false},
		{"400 - token valid, payload rejected", http.StatusBadRequest, true, false},
		{"401 - token incorrect", http.StatusUnauthorized, false, false},
		{"403 - token incorrect", http.StatusForbidden, false, false},
		{"429 - rate limited", http.StatusTooManyRequests, false, true},
		{"404 - unexpected, unverified", http.StatusNotFound, false, false},
		{"422 - unexpected, unverified", http.StatusUnprocessableEntity, false, false},
		{"500 - server error", http.StatusInternalServerError, false, true},
		{"503 - server unavailable", http.StatusServiceUnavailable, false, true},
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

// A 500 from one endpoint followed by a 401 from another should preserve the
// transient error. The 401 means "not recognized here" — it shouldn't erase
// the uncertainty from the earlier failure.
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

// A 500 from the first endpoint followed by a 400 (verified) from the second
// should clear the transient error and mark the result as verified.
func TestHumioIngestToken_Verification_ErrorClearedOnSuccess(t *testing.T) {
	ts500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts500.Close()

	ts400 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts400.Close()

	s := Scanner{}
	_ = s.SetConfiguredEndpoints(ts500.URL, ts400.URL)

	input := fmt.Sprintf("humio_token = '%s'", validPattern)
	results, err := s.FromData(context.Background(), true, []byte(input))
	if err != nil {
		t.Fatalf("FromData error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if !r.Verified {
		t.Error("expected Verified = true")
	}
	if r.VerificationError() != nil {
		t.Errorf("expected no verification error, got: %v", r.VerificationError())
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
