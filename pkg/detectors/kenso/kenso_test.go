package kenso

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// Synthetic keys in the exact shape Kenso issues, with valid checksums.
// Not real credentials.
const (
	liveKey = "kenso_live_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG3gUfIC"
	testKey = "kenso_test_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG3oU0y4"
)

func TestKenso_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - live key",
			input: "KENSO_API_KEY=" + liveKey,
			want:  []string{liveKey},
		},
		{
			name:  "valid pattern - test key",
			input: `{"kensoApiKey": "` + testKey + `"}`,
			want:  []string{testKey},
		},
		{
			name: "valid pattern - live and test keys, duplicates reported once",
			input: `curl -H "Authorization: Bearer ` + liveKey + `" https://api.ken.so/v1/me
				KENSO_SANDBOX_KEY=` + testKey + `
				KENSO_API_KEY=` + liveKey,
			want: []string{liveKey, testKey},
		},
		{
			name:  "invalid pattern - one character changed",
			input: "KENSO_API_KEY=kenso_live_AbCdEfGhIxKlMnOpQrStUvWxYz0123456789AbCdEfG3gUfIC",
			want:  nil,
		},
		{
			name:  "invalid pattern - checksum character changed",
			input: "KENSO_API_KEY=kenso_live_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG3gUfID",
			want:  nil,
		},
		{
			name:  "invalid pattern - live key relabelled as test key",
			input: "KENSO_API_KEY=kenso_test_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG3gUfIC",
			want:  nil,
		},
		{
			name:  "invalid pattern - too long",
			input: "KENSO_API_KEY=" + liveKey + "a",
			want:  nil,
		},
		{
			name:  "invalid pattern - legacy ken_ key without checksum",
			input: "KENSO_API_KEY=ken_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG",
			want:  nil,
		},
		{
			name:  "invalid pattern - variable name only",
			input: "KENSO_API_KEY=",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
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

func TestKenso_Verification(t *testing.T) {
	errTransport := errors.New("transport failure")

	tests := []struct {
		name         string
		key          string
		responseCode int
		transportErr error
		wantVerified bool
		wantErr      string
	}{
		{name: "200 OK - verified", key: liveKey, responseCode: http.StatusOK, wantVerified: true},
		{name: "200 OK - test key verified", key: testKey, responseCode: http.StatusOK, wantVerified: true},
		{name: "401 Unauthorized - unverified", key: liveKey, responseCode: http.StatusUnauthorized},
		{name: "403 Forbidden - verification error", key: liveKey, responseCode: http.StatusForbidden, wantErr: "unexpected HTTP response status 403"},
		{name: "429 Too Many Requests - verification error", key: liveKey, responseCode: http.StatusTooManyRequests, wantErr: "unexpected HTTP response status 429"},
		{name: "500 Internal Server Error - verification error", key: liveKey, responseCode: http.StatusInternalServerError, wantErr: "unexpected HTTP response status 500"},
		{name: "transport failure - verification error", key: liveKey, transportErr: errTransport, wantErr: errTransport.Error()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{client: &http.Client{Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					if req.Method != http.MethodGet {
						t.Errorf("method = %s, want GET", req.Method)
					}
					if got := req.URL.String(); got != "https://api.ken.so/v1/me" {
						t.Errorf("url = %s", got)
					}
					if got := req.Header.Get("Authorization"); got != "Bearer "+tt.key {
						t.Errorf("Authorization = %q", got)
					}
					if got := req.Header.Get("Ken-Version"); got != "1.1" {
						t.Errorf("Ken-Version = %q, want 1.1", got)
					}
					if tt.transportErr != nil {
						return nil, tt.transportErr
					}
					return &http.Response{
						Request:    req,
						StatusCode: tt.responseCode,
						Body:       io.NopCloser(strings.NewReader("{}")),
					}, nil
				},
			}}}

			results, err := s.FromData(context.Background(), true, []byte("KENSO_API_KEY="+tt.key))
			if err != nil {
				t.Fatalf("FromData error = %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("got %d results, want 1", len(results))
			}
			r := results[0]

			if r.Verified != tt.wantVerified {
				t.Errorf("Verified = %v, want %v", r.Verified, tt.wantVerified)
			}
			verificationErr := r.VerificationError()
			if tt.wantErr == "" {
				if verificationErr != nil {
					t.Errorf("unexpected verification error: %v", verificationErr)
				}
			} else if verificationErr == nil || !strings.Contains(verificationErr.Error(), tt.wantErr) {
				t.Errorf("verification error = %v, want it to contain %q", verificationErr, tt.wantErr)
			}
			if got := r.SecretParts["key"]; got != tt.key {
				t.Errorf("SecretParts[key] = %q, want %q", got, tt.key)
			}
		})
	}
}

func TestKenso_InvalidChecksumIsNeverSent(t *testing.T) {
	s := Scanner{client: &http.Client{Transport: common.FakeTransport{
		CreateResponse: func(req *http.Request) (*http.Response, error) {
			t.Errorf("unexpected request for %s", req.Header.Get("Authorization"))
			return nil, errors.New("no request expected")
		},
	}}}

	input := "KENSO_API_KEY=kenso_live_AbCdEfGhIxKlMnOpQrStUvWxYz0123456789AbCdEfG3gUfIC"
	results, err := s.FromData(context.Background(), true, []byte(input))
	if err != nil {
		t.Fatalf("FromData error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("got %d results, want 0", len(results))
	}
}
