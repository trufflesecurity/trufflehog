package workos

import (
	"context"
	"encoding/base64"
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

// Fake keys are built at runtime so the source contains no key-shaped strings for secret scanners to flag.
// They aren't real WorkOS credentials.
var (
	testKey  = fakeKey("test", "key_01HZX4K8J2Q9N3V5T7W6Y8Z0AB,FakeSecretValue0123456789")
	testKey2 = fakeKey("test", "key_01J0M2P4R6T8V0X2Z4B6D8F0HK,NotARealSecretForTests123")
	liveKey  = fakeKey("live", "key_01HZX4K8J2Q9N3V5T7W6Y8Z0AB,FakeSecretValue0123456789")
	// Starts with base64("key_01") but doesn't decode to a key ID.
	badShapeKey = fakeKey("test", "key_01not-a-ulid-at-all-here!!,secretvaluesecretvalue")
)

func fakeKey(environment, payload string) string {
	return "sk_" + environment + "_" + base64.RawStdEncoding.EncodeToString([]byte(payload))
}

func TestWorkOS_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "env file",
			input: "WORKOS_API_KEY=" + testKey,
			want:  []string{testKey},
		},
		{
			name:  "live key in json",
			input: `{"workosApiKey": "` + liveKey + `"}`,
			want:  []string{liveKey},
		},
		{
			name:  "launchSettings with two keys",
			input: `"WORKOS_API_KEY": "` + testKey + `", "OTHER": "` + testKey2 + `"`,
			want:  []string{testKey, testKey2},
		},
		{
			name:  "padded key",
			input: "export WORKOS_API_KEY='" + testKey + "='",
			want:  []string{testKey + "="},
		},
		{
			name:  "invalid pattern: wrong decoded shape",
			input: "WORKOS_API_KEY=" + badShapeKey,
			want:  nil,
		},
		{
			name:  "invalid pattern: stripe key",
			input: "STRIPE_SECRET_KEY=sk_test_51HZX4K8J2Q9N3V5T7W6Y8Z0ABFakeSecretValue0123456789",
			want:  nil,
		},
		{
			name:  "invalid pattern: legacy WorkOS key format",
			input: "WORKOS_API_KEY=sk_test_FakeLegacyKey0123456789ab",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(detectorMatches) == 0 {
				if len(test.want) > 0 {
					t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				}
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
				if isFP, reason := d.IsFalsePositive(r); isFP {
					t.Errorf("result flagged as false positive: %s", reason)
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

func TestWorkOS_ExtraData(t *testing.T) {
	results, err := Scanner{}.FromData(context.Background(), false, []byte("WORKOS_API_KEY="+liveKey))
	if err != nil {
		t.Fatalf("FromData error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	want := map[string]string{"key_id": "key_01HZX4K8J2Q9N3V5T7W6Y8Z0AB", "environment": "live"}
	if diff := cmp.Diff(want, results[0].ExtraData); diff != "" {
		t.Errorf("ExtraData diff: (-want +got)\n%s", diff)
	}
	if got := results[0].SecretParts["key"]; got != liveKey {
		t.Errorf("SecretParts[key] = %q, want %q", got, liveKey)
	}
}

func TestWorkOS_VerifyMatch(t *testing.T) {
	errTransport := errors.New("transport failure")

	tests := []struct {
		name         string
		responseCode int
		transportErr error
		wantVerified bool
		wantErr      string
	}{
		{name: "200 OK - verified", responseCode: http.StatusOK, wantVerified: true},
		{name: "401 Unauthorized - unverified", responseCode: http.StatusUnauthorized},
		{name: "403 Forbidden - verification error", responseCode: http.StatusForbidden, wantErr: "unexpected HTTP response status 403"},
		{name: "429 Too Many Requests - verification error", responseCode: http.StatusTooManyRequests, wantErr: "unexpected HTTP response status 429"},
		{name: "500 Internal Server Error - verification error", responseCode: http.StatusInternalServerError, wantErr: "unexpected HTTP response status 500"},
		{name: "transport failure - verification error", transportErr: errTransport, wantErr: errTransport.Error()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{client: &http.Client{Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					if req.Method != http.MethodGet {
						t.Errorf("method = %s, want GET", req.Method)
					}
					if got := req.URL.String(); got != "https://api.workos.com/organizations?limit=1" {
						t.Errorf("url = %s", got)
					}
					if got := req.Header.Get("Authorization"); got != "Bearer "+testKey {
						t.Errorf("Authorization = %q", got)
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

			results, err := s.FromData(context.Background(), true, []byte("WORKOS_API_KEY="+testKey))
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
		})
	}
}
