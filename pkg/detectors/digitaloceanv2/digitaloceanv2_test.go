package digitaloceanv2

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

var (
	validPattern = `
		# Configuration File: config.yaml
		database:
			host: $DB_HOST
			port: $DB_PORT
			username: $DB_USERNAME
			password: $DB_PASS  # IMPORTANT: Do not share this password publicly

		api:
			auth_type: "API-Key"
			in: "Path"
			digitalocean_secret1: "doo_v1_997deb722a2cf8f14a2eef30e41ed96e08268603b7877a595504e4367ca58e3d"
			digitalocean_secret2: "dop_v1_997deb722a2cf8f14a2eef30e41ed96e08268603b7877a595504e4367ca58e3d"
			digitalocean_secret3: "dor_v1_997deb722a2cf8f14a2eef30e41ed96e08268603b7877a595504e4367ca58e3d"
			base_url: "https://api.example.com/v1/example?refresh_token=$digitalocean_secret1"
			response_code: 200

		# Notes:
		# - Remember to rotate the secret every 90 days.
		# - The above credentials should only be used in a secure environment.
	`
	secrets = []string{
		"doo_v1_997deb722a2cf8f14a2eef30e41ed96e08268603b7877a595504e4367ca58e3d",
		"dop_v1_997deb722a2cf8f14a2eef30e41ed96e08268603b7877a595504e4367ca58e3d",
		"dor_v1_997deb722a2cf8f14a2eef30e41ed96e08268603b7877a595504e4367ca58e3d",
	}
)

func TestDigitalOceanV2_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: validPattern,
			want:  secrets,
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestDigitalOceanV2_AccessTokenVerification(t *testing.T) {
	tests := []struct {
		name                  string
		token                 string
		status                int
		body                  string
		requestErr            error
		skipVerification      bool
		wantVerified          bool
		wantVerificationError bool
	}{
		{
			name: "model access key", token: secrets[0], status: http.StatusOK,
			body:         `{"resource_owner_id":123,"scopes":["inference:query"],"expires_in_seconds":null,"application":{"uid":"test-app"},"created_at":1700000000}`,
			wantVerified: true,
		},
		{
			name: "personal access token", token: secrets[1], status: http.StatusOK,
			body:         `{"resource_owner_id":123,"scopes":["read"],"expires_in_seconds":7776000,"application":{"uid":"test-app"},"created_at":1700000000}`,
			wantVerified: true,
		},
		{name: "success without metadata", token: secrets[0], status: http.StatusOK, wantVerified: true},
		{name: "unauthorized", token: secrets[0], status: http.StatusUnauthorized},
		{name: "forbidden", token: secrets[1], status: http.StatusForbidden, wantVerificationError: true},
		{name: "rate limited", token: secrets[0], status: http.StatusTooManyRequests, wantVerificationError: true},
		{name: "server error", token: secrets[1], status: http.StatusInternalServerError, wantVerificationError: true},
		{name: "network error", token: secrets[0], requestErr: errors.New("network unavailable"), wantVerificationError: true},
		{name: "verification disabled", token: secrets[0], skipVerification: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			s := Scanner{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.Method != http.MethodGet || req.URL.String() != "https://cloud.digitalocean.com/v1/oauth/token/info" {
					t.Errorf("unexpected verification request: %s %s", req.Method, req.URL)
				}
				if got := req.Header.Get("Authorization"); got != "Bearer "+tt.token {
					t.Error("unexpected authorization header")
				}
				if tt.requestErr != nil {
					return nil, tt.requestErr
				}
				return &http.Response{StatusCode: tt.status, Body: io.NopCloser(strings.NewReader(tt.body)), Header: make(http.Header)}, nil
			})}}

			results, err := s.FromData(context.Background(), !tt.skipVerification, []byte(tt.token))
			if err != nil {
				t.Fatal(err)
			}
			wantRequests := 1
			if tt.skipVerification {
				wantRequests = 0
			}
			if requests != wantRequests {
				t.Errorf("expected %d verification requests, got %d", wantRequests, requests)
			}
			if len(results) != 1 {
				t.Fatalf("expected one result, got %d", len(results))
			}
			result := results[0]
			if result.Verified != tt.wantVerified {
				t.Errorf("Verified = %v, want %v", result.Verified, tt.wantVerified)
			}
			if (result.VerificationError() != nil) != tt.wantVerificationError {
				t.Errorf("unexpected verification error: %v", result.VerificationError())
			}
			if result.ExtraData != nil {
				t.Errorf("expected no extra data, got %v", result.ExtraData)
			}
			if result.DetectorType != detector_typepb.DetectorType_DigitalOceanV2 || string(result.Raw) != tt.token {
				t.Error("unexpected detector type or raw token")
			}
			if diff := cmp.Diff(map[string]string{"key": tt.token}, result.SecretParts); diff != "" {
				t.Errorf("SecretParts diff (-want +got):\n%s", diff)
			}
		})
	}
}
