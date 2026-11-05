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
	sandboxKey    = fakeKey("sk_test_", "key_01HZX4K8J2Q9N3V5T7W6Y8Z0AB,FakeSecretValue0123456789")
	sandboxKey2   = fakeKey("sk_test_", "key_01J0M2P4R6T8V0X2Z4B6D8F0HK,NotARealSecretForTests123")
	productionKey = fakeKey("sk_", "key_01HZX4K8J2Q9N3V5T7W6Y8Z0AB,FakeSecretValue0123456789")
	// ULIDs created after 2039 start with "02", and later ones with a letter in the second position.
	futureKey  = fakeKey("sk_", "key_02HZX4K8J2Q9N3V5T7W6Y8Z0AB,FakeSecretValue0123456789")
	futureKey2 = fakeKey("sk_", "key_0ZHZX4K8J2Q9N3V5T7W6Y8Z0AB,FakeSecretValue0123456789")
	// Same length and prefix as a real key, but the ID isn't a ULID.
	badShapeKey = fakeKey("sk_test_", "key_01"+strings.Repeat("z", 24)+",FakeSecretValue0123456789")
	// WorkOS never issues sk_live_ keys in this format.
	liveShapeKey = fakeKey("sk_live_", "key_01HZX4K8J2Q9N3V5T7W6Y8Z0AB,FakeSecretValue0123456789")

	issuedKey = "sk_" + "FakeOrgKeyValue12345" + "w3rk0s" + "NotARealUserKey67890"
)

func fakeKey(prefix, payload string) string {
	return prefix + base64.RawStdEncoding.EncodeToString([]byte(payload))
}

func TestWorkOS_Pattern(t *testing.T) {
	if !environmentKeyPat.MatchString(badShapeKey) {
		t.Fatal("badShapeKey must match the regex so the decode check is what rejects it")
	}

	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "sandbox key in env file",
			input: "WORKOS_API_KEY=" + sandboxKey,
			want:  []string{sandboxKey},
		},
		{
			name:  "production key in json",
			input: `{"workosApiKey": "` + productionKey + `"}`,
			want:  []string{productionKey},
		},
		{
			name:  "launchSettings with two keys",
			input: `"WORKOS_API_KEY": "` + sandboxKey + `", "OTHER": "` + sandboxKey2 + `"`,
			want:  []string{sandboxKey, sandboxKey2},
		},
		{
			name:  "keys with future ULIDs",
			input: "A=" + futureKey + "\nB=" + futureKey2,
			want:  []string{futureKey, futureKey2},
		},
		{
			name:  "organization or user API key",
			input: "Authorization: Bearer " + issuedKey,
			want:  []string{issuedKey},
		},
		{
			name:  "invalid pattern: wrong decoded shape",
			input: "WORKOS_API_KEY=" + badShapeKey,
			want:  nil,
		},
		{
			name:  "invalid pattern: sk_live_ prefix",
			input: "WORKOS_API_KEY=" + liveShapeKey,
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
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "production key",
			input: productionKey,
			want:  map[string]string{"key_type": "environment_api_key", "key_id": "key_01HZX4K8J2Q9N3V5T7W6Y8Z0AB", "environment": "production"},
		},
		{
			name:  "sandbox key",
			input: sandboxKey,
			want:  map[string]string{"key_type": "environment_api_key", "key_id": "key_01HZX4K8J2Q9N3V5T7W6Y8Z0AB", "environment": "sandbox"},
		},
		{
			name:  "organization or user API key",
			input: issuedKey,
			want:  map[string]string{"key_type": "organization_or_user_api_key"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := Scanner{}.FromData(context.Background(), false, []byte("KEY="+tt.input))
			if err != nil {
				t.Fatalf("FromData error = %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("got %d results, want 1", len(results))
			}
			if diff := cmp.Diff(tt.want, results[0].ExtraData); diff != "" {
				t.Errorf("ExtraData diff: (-want +got)\n%s", diff)
			}
			if got := results[0].SecretParts["key"]; got != tt.input {
				t.Errorf("SecretParts[key] = %q, want %q", got, tt.input)
			}
		})
	}
}

func TestWorkOS_IssuedKeyIsNotVerified(t *testing.T) {
	s := Scanner{client: &http.Client{Transport: common.FakeTransport{
		CreateResponse: func(req *http.Request) (*http.Response, error) {
			t.Errorf("unexpected request to %s", req.URL)
			return nil, errors.New("unexpected request")
		},
	}}}

	results, err := s.FromData(context.Background(), true, []byte("KEY="+issuedKey))
	if err != nil {
		t.Fatalf("FromData error = %v", err)
	}
	if len(results) != 1 || results[0].Verified || results[0].VerificationError() != nil {
		t.Errorf("want one unverified result without a verification error, got %+v", results)
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
					if got := req.Header.Get("Authorization"); got != "Bearer "+sandboxKey {
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

			results, err := s.FromData(context.Background(), true, []byte("WORKOS_API_KEY="+sandboxKey))
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
