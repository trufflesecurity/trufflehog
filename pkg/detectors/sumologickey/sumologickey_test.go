package sumologickey

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"

	"github.com/google/go-cmp/cmp"
)

// verifyInput names one access ID and key and no regional URL, so the only
// endpoints verification can reach are the ones a test configures.
const verifyInput = `sumologic:
  accessId: suDkVYKjXZAwsz
  accessKey: Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL`

func TestSumoLogicKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "typical pattern",
			input: `sumologic:
  accessId: suDkVYKjXZAwsz
  accessKey: Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL
  clusterName: Kubernetes_cluster-2024-10-25T21:34:23.096Z`,
			want: []string{`{"accessId":"suDkVYKjXZAwsz","accessKey":"Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL"}`},
		},
		{
			name: "pattern with url",
			input: `sumologic:
  baseUrl: api.us2.sumologic.com
  accessId: suDkVYKjXZAwsz
  accessKey: Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL
  clusterName: Kubernetes_cluster-2024-10-25T21:34:23.096Z`,
			want: []string{`{"accessId":"suDkVYKjXZAwsz","accessKey":"Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL","url":"api.us2.sumologic.com"}`},
		},
		{
			name: "finds all matches",
			input: `sumoId1 = 'suaRYt6iLL8cxl'
sumoKey1 = 'CzrMhR8zzy1eH1F0XlY1tu5ywqa2yaSFoWGg2cqE43XkfnUVCytnPQfv1enUYrzv'
sumoId2 = 'suDkVYKjXZBwsz'
sumoKey2 = 'Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK21a0LckgRSCL'`,
			want: []string{"CzrMhR8zzy1eH1F0XlY1tu5ywqa2yaSFoWGg2cqE43XkfnUVCytnPQfv1enUYrzv", "Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK21a0LckgRSCL"},
		},
		{
			name:  "invalid pattern",
			input: "sumoId = 'doDkVYKjXZAwsz'",
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

// Exercise verification against a mock server configured as a verifier
// endpoint, so a request only arrives if FromData verifies through
// Endpoints(). A verified result keeps the same RawV2 an unverified one
// would have, and reports the endpoint in ExtraData instead.
func TestSumoLogicKey_Verification(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		wantVerified bool
		wantErr      bool
	}{
		{"200 - valid key", http.StatusOK, true, false},
		{"401 - invalid key", http.StatusUnauthorized, false, false},
		{"500 - server error", http.StatusInternalServerError, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer ts.Close()

			s := Scanner{}
			_ = s.SetConfiguredEndpoints(ts.URL)

			results, err := s.FromData(context.Background(), true, []byte(verifyInput))
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
			wantRawV2 := `{"accessId":"suDkVYKjXZAwsz","accessKey":"Khk3i2ugMxMgkb8bIA2auj4I8juZ3HiimDNssjzYdGqfizPZcxHK70a0LckgRSCL"}`
			if string(r.RawV2) != wantRawV2 {
				t.Errorf("RawV2 = %s, want %s", r.RawV2, wantRawV2)
			}
			if tt.wantVerified && r.ExtraData["endpoint"] != ts.URL {
				t.Errorf("ExtraData[endpoint] = %q, want %q", r.ExtraData["endpoint"], ts.URL)
			}
			if tt.wantVerified && r.ExtraData["access_id"] != "suDkVYKjXZAwsz" {
				t.Errorf("ExtraData[access_id] = %q, want %q", r.ExtraData["access_id"], "suDkVYKjXZAwsz")
			}
		})
	}
}

// Verify that a successful verification on a later endpoint clears any
// error from an earlier failed attempt (e.g. first endpoint returns 500,
// second returns 200).
func TestSumoLogicKey_Verification_StaleErrorCleared(t *testing.T) {
	ts500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts500.Close()

	ts200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts200.Close()

	s := Scanner{}
	_ = s.SetConfiguredEndpoints(ts500.URL, ts200.URL)

	results, err := s.FromData(context.Background(), true, []byte(verifyInput))
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
func TestSumoLogicKey_Verification_ErrorPreservedAcross401(t *testing.T) {
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

	results, err := s.FromData(context.Background(), true, []byte(verifyInput))
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
