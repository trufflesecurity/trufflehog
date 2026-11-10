package nuntiq

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

// Format-valid credentials with a correct checksum that were never issued: they cannot
// authenticate anywhere.
const (
	customerKey    = "nuntiq_ck_live_1787e770_Cx3BT1zw4XhBmOwTNnTzqXVssmZWnD8n-XosQLWqXJI0fil7C"
	partnerKey     = "nuntiq_pk_live_326e932b_pcvLCgsshxMD84d2YyG8mqrkXIcXBG0-YhknB7Q6zDU3ggTr8"
	rotationSecret = "nuntiq_rs_live_21de8760_SqPffdMtVohhIsr6xV3cb9KQeXZ33W2DY2jtbXBeY0Q2ESzMW"
	testEnvKey     = "nuntiq_ck_test_e8bcfd3f_IwlPImwzSnmfIZ7hFLDQea4xhIznzZvKRPzBU5D0WSQ457xL8"
)

func TestNuntiq_Checksum(t *testing.T) {
	for _, key := range []string{customerKey, partnerKey, rotationSecret, testEnvKey} {
		tail := key[len(key)-49:]
		if got, want := checksum(tail[:43]), tail[43:]; got != want {
			t.Errorf("checksum(%s) = %s, want %s", tail[:43], got, want)
		}
	}
}

func TestNuntiq_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "env assignment",
			input: "NUNTIQ_API_KEY=" + customerKey,
			want:  []string{customerKey},
		},
		{
			name:  "json header",
			input: `{"X-API-Key": "` + partnerKey + `"}`,
			want:  []string{partnerKey},
		},
		{
			name:  "yaml rotation secret",
			input: "rotation_secret: " + rotationSecret,
			want:  []string{rotationSecret},
		},
		{
			name:  "curl header, test environment",
			input: `curl -H "X-API-Key: ` + testEnvKey + `" https://test-api.apreceiving.com/api/v1/ping`,
			want:  []string{testEnvKey},
		},
		{
			name:  "adjacent keys",
			input: customerKey + "," + partnerKey + " " + customerKey,
			want:  []string{customerKey, partnerKey},
		},
		{
			name:  "invalid pattern - wrong checksum",
			input: "NUNTIQ_API_KEY=" + customerKey[:len(customerKey)-1] + "D",
			want:  nil,
		},
		{
			name:  "invalid pattern - longer token",
			input: "NUNTIQ_API_KEY=" + customerKey + "x",
			want:  nil,
		},
		{
			name:  "invalid pattern - display form",
			input: "key: nuntiq_ck_live_1a2b3c4d...wXyZ",
			want:  nil,
		},
		{
			name:  "invalid pattern - unknown kind",
			input: "nuntiq_xk_live_1787e770_Cx3BT1zw4XhBmOwTNnTzqXVssmZWnD8n-XosQLWqXJI0fil7C nuntiq_ck_",
			want:  nil,
		},
		{
			name:  "invalid pattern - unknown environment",
			input: "nuntiq_ck_prod_1787e770_Cx3BT1zw4XhBmOwTNnTzqXVssmZWnD8n-XosQLWqXJI0fil7C",
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
				if got := r.SecretParts["key"]; got != string(r.Raw) {
					t.Errorf("SecretParts[key] = %q, want %q", got, r.Raw)
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

func TestNuntiq_ExtraData(t *testing.T) {
	results, err := Scanner{}.FromData(context.Background(), false, []byte(rotationSecret+" "+testEnvKey))
	if err != nil || len(results) != 2 {
		t.Fatalf("FromData = %d results, error %v", len(results), err)
	}
	want := map[string]map[string]string{
		rotationSecret: {"kind": "rotation_secret", "environment": "live"},
		testEnvKey:     {"kind": "customer_api_key", "environment": "test"},
	}
	for _, r := range results {
		if diff := cmp.Diff(want[string(r.Raw)], r.ExtraData); diff != "" {
			t.Errorf("ExtraData diff: (-want +got)\n%s", diff)
		}
	}
}

func TestNuntiq_NotAFalsePositive(t *testing.T) {
	results, err := Scanner{}.FromData(context.Background(), false, []byte(testEnvKey))
	if err != nil || len(results) != 1 {
		t.Fatalf("FromData = %d results, error %v", len(results), err)
	}
	if fp, reason := detectors.GetFalsePositiveCheck(Scanner{})(results[0]); fp {
		t.Errorf("test-environment key reported as false positive: %s", reason)
	}
}

func TestNuntiq_VerifyMatch(t *testing.T) {
	errTransport := errors.New("transport failure")

	tests := []struct {
		name         string
		key          string
		wantURL      string
		responseCode int
		body         string
		transportErr error
		wantVerified bool
		wantErr      string
	}{
		{
			name: "valid - verified", key: customerKey, wantURL: "https://api.apreceiving.com/api/v1/key-check",
			responseCode: http.StatusOK, body: `{"valid":true,"kind":"customer_api_key","environment":"live"}`, wantVerified: true,
		},
		{
			name: "not valid - unverified", key: customerKey, wantURL: "https://api.apreceiving.com/api/v1/key-check",
			responseCode: http.StatusOK, body: `{"valid":false,"kind":null,"environment":null}`,
		},
		{
			name: "test environment host", key: testEnvKey, wantURL: "https://test-api.apreceiving.com/api/v1/key-check",
			responseCode: http.StatusOK, body: `{"valid":true,"kind":"customer_api_key","environment":"test"}`, wantVerified: true,
		},
		{
			name: "missing valid field - verification error", key: customerKey, wantURL: "https://api.apreceiving.com/api/v1/key-check",
			responseCode: http.StatusOK, body: `{}`, wantErr: "no valid field",
		},
		{
			name: "non-JSON body - verification error", key: customerKey, wantURL: "https://api.apreceiving.com/api/v1/key-check",
			responseCode: http.StatusOK, body: `<html>`, wantErr: "invalid character",
		},
		{
			name: "429 - verification error", key: customerKey, wantURL: "https://api.apreceiving.com/api/v1/key-check",
			responseCode: http.StatusTooManyRequests, body: `{}`, wantErr: "unexpected HTTP response status 429",
		},
		{
			name: "500 - verification error", key: customerKey, wantURL: "https://api.apreceiving.com/api/v1/key-check",
			responseCode: http.StatusInternalServerError, body: `{}`, wantErr: "unexpected HTTP response status 500",
		},
		{
			name: "transport failure - verification error", key: customerKey, wantURL: "https://api.apreceiving.com/api/v1/key-check",
			transportErr: errTransport, wantErr: errTransport.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{client: &http.Client{Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					if req.Method != http.MethodPost {
						t.Errorf("method = %s, want POST", req.Method)
					}
					if got := req.URL.String(); got != tt.wantURL {
						t.Errorf("url = %s, want %s", got, tt.wantURL)
					}
					if got := req.Header.Get("X-API-Key"); got != tt.key {
						t.Errorf("X-API-Key = %q, want %q", got, tt.key)
					}
					if tt.transportErr != nil {
						return nil, tt.transportErr
					}
					return &http.Response{
						Request:    req,
						StatusCode: tt.responseCode,
						Body:       io.NopCloser(strings.NewReader(tt.body)),
					}, nil
				},
			}}}

			results, err := s.FromData(context.Background(), true, []byte("NUNTIQ_API_KEY="+tt.key))
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
