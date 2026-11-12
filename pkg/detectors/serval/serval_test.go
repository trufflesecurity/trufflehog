package serval

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

// Synthetic secrets in the exact shape Serval issues, with valid checksums.
// Not real credentials.
var (
	publicSecret        = "svl_secret_pk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg3VqCUe"
	workerSecret        = "svl_secret_wk_hijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN24D8Sa"
	managedWorkerSecret = "svl_secret_mk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg182p0W"
	clientID            = "3f1c2a9e-8b7d-4e6f-9a0b-1c2d3e4f5a6b"
)

func TestServal_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - public key with client id",
			input: `
				SERVAL_CLIENT_ID=` + clientID + `
				SERVAL_CLIENT_SECRET=` + publicSecret,
			want: []string{clientID + ":" + publicSecret},
		},
		{
			name:  "valid pattern - uppercase client id is normalized",
			input: `serval client_id: "3F1C2A9E-8B7D-4E6F-9A0B-1C2D3E4F5A6B" secret: ` + publicSecret,
			want:  []string{clientID + ":" + publicSecret},
		},
		{
			name:  "valid pattern - secret without client id",
			input: `token = "` + publicSecret + `"`,
			want:  []string{publicSecret},
		},
		{
			name:  "valid pattern - worker key",
			input: `SERVAL_WORKER_SECRET=` + workerSecret,
			want:  []string{workerSecret},
		},
		{
			name:  "valid pattern - managed worker key",
			input: `secret: ` + managedWorkerSecret,
			want:  []string{managedWorkerSecret},
		},
		{
			name:  "invalid pattern - checksum mismatch",
			input: `SERVAL_CLIENT_SECRET=svl_secret_pk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg3VqCUf`,
			want:  nil,
		},
		{
			name:  "invalid pattern - checksum valid for another key type",
			input: `SERVAL_CLIENT_SECRET=svl_secret_wk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg3VqCUe`,
			want:  nil,
		},
		{
			name:  "invalid pattern - unknown key type",
			input: `SERVAL_CLIENT_SECRET=svl_secret_xk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg3VqCUe`,
			want:  nil,
		},
		{
			name:  "invalid pattern - too long",
			input: `SERVAL_CLIENT_SECRET=` + publicSecret + `a`,
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
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
				if r.SecretParts["client_secret"] != string(r.Raw) {
					t.Errorf("SecretParts[client_secret] = %q, want %q", r.SecretParts["client_secret"], r.Raw)
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

// tokenServer replies with status to every request and counts them. It fails
// the test unless each request is a client credentials grant for clientID
// and publicSecret.
func tokenServer(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v2/auth/token" {
			t.Errorf("unexpected request %s %s, want POST /v2/auth/token", r.Method, r.URL.Path)
		}
		if id, secret, ok := r.BasicAuth(); !ok || id != clientID || secret != publicSecret {
			t.Errorf("basic auth = (%q, %q, %v), want (%q, %q, true)", id, secret, ok, clientID, publicSecret)
		}
		if got := r.FormValue("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q, want client_credentials", got)
		}
		w.WriteHeader(status)
	}))
	return ts, &hits
}

func TestServal_VerifyKeyStatuses(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		wantVerified bool
		wantErr      bool
	}{
		{name: "200 verified", status: http.StatusOK, wantVerified: true},
		{name: "401 determinately invalid", status: http.StatusUnauthorized},
		{name: "400 indeterminate", status: http.StatusBadRequest, wantErr: true},
		{name: "429 indeterminate", status: http.StatusTooManyRequests, wantErr: true},
		{name: "502 indeterminate", status: http.StatusBadGateway, wantErr: true},
		{name: "503 indeterminate", status: http.StatusServiceUnavailable, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts, _ := tokenServer(t, test.status)
			defer ts.Close()

			verified, err := verifyKey(context.Background(), ts.Client(), ts.URL, clientID, publicSecret)
			if verified != test.wantVerified {
				t.Errorf("verified = %v, want %v", verified, test.wantVerified)
			}
			if (err != nil) != test.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, test.wantErr)
			}
		})
	}
}

func TestServal_FromDataVerification(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		status       int
		wantVerified bool
		wantErr      bool
		wantRequests int32
	}{
		{
			name:         "public key verifies",
			input:        "serval client_id=" + clientID + " client_secret=" + publicSecret,
			status:       http.StatusOK,
			wantVerified: true,
			wantRequests: 1,
		},
		{
			name:         "public key rejected",
			input:        "serval client_id=" + clientID + " client_secret=" + publicSecret,
			status:       http.StatusUnauthorized,
			wantRequests: 1,
		},
		{
			name:         "rate limit is indeterminate",
			input:        "serval client_id=" + clientID + " client_secret=" + publicSecret,
			status:       http.StatusTooManyRequests,
			wantErr:      true,
			wantRequests: 1,
		},
		{
			name:         "worker key is not sent for verification",
			input:        "serval client_id=" + clientID + " client_secret=" + workerSecret,
			status:       http.StatusOK,
			wantRequests: 0,
		},
		{
			name:         "secret without client id is not sent for verification",
			input:        "client_secret=" + publicSecret,
			status:       http.StatusOK,
			wantRequests: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts, hits := tokenServer(t, test.status)
			defer ts.Close()

			d := Scanner{client: ts.Client(), endpoints: []string{ts.URL}}
			results, err := d.FromData(context.Background(), true, []byte(test.input))
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
			if got := hits.Load(); got != test.wantRequests {
				t.Errorf("requests = %d, want %d", got, test.wantRequests)
			}
		})
	}
}

func TestServal_StopsAfterVerifiedPair(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if id, secret, _ := r.BasicAuth(); id == clientID && secret == publicSecret {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	input := "serval client_secret=" + publicSecret + "\n" +
		"client_id=11111111-1111-4111-8111-111111111111\n" +
		"client_id=22222222-2222-4222-8222-222222222222\n" +
		"client_id=33333333-3333-4333-8333-333333333333\n" +
		"client_id=44444444-4444-4444-8444-444444444444\n" +
		"client_id=" + clientID + "\n"

	// Client IDs come out of a map in random order, so repeat to make a
	// missing early exit show up as a verified result that is not last.
	d := Scanner{client: ts.Client(), endpoints: []string{ts.URL}}
	for i := 0; i < 20; i++ {
		hits.Store(0)
		results, err := d.FromData(context.Background(), true, []byte(input))
		if err != nil {
			t.Fatalf("FromData: %v", err)
		}
		if got := hits.Load(); got != int32(len(results)) {
			t.Fatalf("requests = %d, want one per result (%d)", got, len(results))
		}
		last := results[len(results)-1]
		if !last.Verified || last.SecretParts["client_id"] != clientID {
			t.Fatalf("last result = verified %v for %q, want the verified pair for %q",
				last.Verified, last.SecretParts["client_id"], clientID)
		}
		for _, r := range results[:len(results)-1] {
			if r.Verified || r.VerificationError() != nil {
				t.Fatalf("pair for %q: verified %v, error %v; want determinately invalid",
					r.SecretParts["client_id"], r.Verified, r.VerificationError())
			}
		}
	}
}

func TestServal_NetworkErrorIsIndeterminate(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	endpoint := ts.URL
	ts.Close()

	verified, err := verifyKey(context.Background(), ts.Client(), endpoint, clientID, publicSecret)
	if verified || err == nil {
		t.Errorf("verifyKey = (%v, %v), want (false, non-nil error)", verified, err)
	}

	d := Scanner{client: ts.Client(), endpoints: []string{endpoint}}
	results, err := d.FromData(context.Background(), true,
		[]byte("serval client_id="+clientID+" client_secret="+publicSecret))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(results) != 1 || results[0].Verified || results[0].VerificationError() == nil {
		t.Fatalf("want one unverified result with a verification error, got %+v", results)
	}
}

func TestServal_RegionFallback(t *testing.T) {
	tests := []struct {
		name         string
		usStatus     int
		euStatus     int
		wantVerified bool
		wantErr      bool
	}{
		{name: "EU key verifies after US 401", usStatus: http.StatusUnauthorized, euStatus: http.StatusOK, wantVerified: true},
		{name: "invalid in both regions", usStatus: http.StatusUnauthorized, euStatus: http.StatusUnauthorized},
		{name: "US rate limit stays indeterminate after EU 401", usStatus: http.StatusTooManyRequests, euStatus: http.StatusUnauthorized, wantErr: true},
		{name: "US key verifies without trying EU", usStatus: http.StatusOK, euStatus: http.StatusInternalServerError, wantVerified: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			us, usHits := tokenServer(t, test.usStatus)
			defer us.Close()
			eu, euHits := tokenServer(t, test.euStatus)
			defer eu.Close()

			d := Scanner{client: us.Client(), endpoints: []string{us.URL, eu.URL}}
			results, err := d.FromData(context.Background(), true,
				[]byte("serval client_id="+clientID+" client_secret="+publicSecret))
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
			if test.usStatus == http.StatusOK {
				if euHits.Load() != 0 {
					t.Errorf("EU requests = %d, want 0 after the US verified", euHits.Load())
				}
				if r.ExtraData["endpoint"] != us.URL {
					t.Errorf("ExtraData[endpoint] = %q, want %q", r.ExtraData["endpoint"], us.URL)
				}
			} else if test.wantVerified && r.ExtraData["endpoint"] != eu.URL {
				t.Errorf("ExtraData[endpoint] = %q, want %q", r.ExtraData["endpoint"], eu.URL)
			}
			if usHits.Load() != 1 {
				t.Errorf("US requests = %d, want 1", usHits.Load())
			}
		})
	}
}
