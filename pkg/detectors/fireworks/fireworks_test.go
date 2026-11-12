package fireworks

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

func TestFireworks_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: "fireworks_api_key = 'fw_3Z9x8Y7w6V5u4T3s2R1q0P9o8N'",
			want:  []string{"fw_3Z9x8Y7w6V5u4T3s2R1q0P9o8N"},
		},
		{
			name:  "pattern inside json",
			input: `{"FIREWORKS_API_KEY": "fw_4AbCdEfGhIjKlMnOpQrStUv" }`,
			want:  []string{"fw_4AbCdEfGhIjKlMnOpQrStUv"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(detectorMatches) == 0 {
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

func TestFireworks_VerifyMatch(t *testing.T) {
	const token = "fw_testkey1234567890123456"
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
					if got := req.URL.String(); got != "https://api.fireworks.ai/inference/v1/models" {
						t.Errorf("url = %s", got)
					}
					if got := req.Header.Get("Authorization"); got != "Bearer "+token {
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

			results, err := s.FromData(context.Background(), true, []byte("FIREWORKS_API_KEY="+token))
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
			if got := r.ExtraData["rotation_guide"]; got != "https://docs.fireworks.ai/api-reference/introduction" {
				t.Errorf("rotation_guide = %q", got)
			}
			if got := r.SecretParts["key"]; got != token {
				t.Errorf("SecretParts[key] = %q, want %q", got, token)
			}
		})
	}
}
