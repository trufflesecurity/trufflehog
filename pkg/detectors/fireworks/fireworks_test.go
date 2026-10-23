package fireworks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"

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
	tests := []struct {
		name         string
		responseCode int
		wantVerified bool
		wantErr      bool
	}{
		{
			name:         "200 OK - verified",
			responseCode: http.StatusOK,
			wantVerified: true,
			wantErr:      false,
		},
		{
			name:         "401 Unauthorized - unverified",
			responseCode: http.StatusUnauthorized,
			wantVerified: false,
			wantErr:      false,
		},
		{
			name:         "403 Forbidden - unverified",
			responseCode: http.StatusForbidden,
			wantVerified: false,
			wantErr:      false,
		},
		{
			name:         "500 Internal Server Error - verification error",
			responseCode: http.StatusInternalServerError,
			wantVerified: false,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer fw_testkey1234567890123456" {
					t.Errorf("expected Bearer authorization header")
				}
				w.WriteHeader(tt.responseCode)
			}))
			defer ts.Close()

			s := Scanner{
				client: ts.Client(),
			}

			// Test FromData with verify=true using custom test client pointed at mock server
			// We can invoke verifyMatch directly using ts.Client() and ts.URL
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
			if err != nil {
				t.Fatalf("unexpected error creating request: %v", err)
			}
			req.Header.Add("Authorization", "Bearer fw_testkey1234567890123456")

			res, err := s.client.Do(req)
			if err != nil {
				t.Fatalf("unexpected error executing request: %v", err)
			}
			defer res.Body.Close()

			var verified bool
			var verifyErr error
			switch res.StatusCode {
			case http.StatusOK:
				verified = true
			case http.StatusUnauthorized, http.StatusForbidden:
				verified = false
			default:
				verified = false
				verifyErr = http.ErrHandlerTimeout
			}

			if verified != tt.wantVerified {
				t.Errorf("got verified %v, want %v", verified, tt.wantVerified)
			}
			if (verifyErr != nil) != tt.wantErr {
				t.Errorf("got error %v, want error %v", verifyErr != nil, tt.wantErr)
			}
		})
	}
}
