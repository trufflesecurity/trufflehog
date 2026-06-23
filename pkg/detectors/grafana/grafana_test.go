package grafana

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `[{
		"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
		"name": "Grafana",
		"type": "Detector",
		"api": true,
		"authentication_type": "",
		"verification_url": "https://api.example.com/example",
		"test_secrets": {
			"grafana_secret": "glc_eyJF057+C0x9J+QwzC5JXb5uQ/WSzn98X/iIrZXKaA3Hh+lum0XBRcu56qMlW7ZaxXrNt33XoI3CXz7IRPci="
		},
		"expected_response": "200",
		"method": "GET",
		"deprecated": false
	}]`
	secret = "glc_eyJF057+C0x9J+QwzC5JXb5uQ/WSzn98X/iIrZXKaA3Hh+lum0XBRcu56qMlW7ZaxXrNt33XoI3CXz7IRPci="
)

func TestGrafana_Pattern(t *testing.T) {
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
			want:  []string{secret},
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

func TestGrafana_Verification(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		body         string
		wantVerified bool
		wantErr      bool
	}{
		{
			name:         "200 OK is verified",
			statusCode:   200,
			body:         `[{"id":"abc"}]`,
			wantVerified: true,
		},
		{
			name:         "403 Forbidden (valid token, restricted permissions) is verified",
			statusCode:   403,
			body:         `{"message":"You'll need additional permissions to perform this action."}`,
			wantVerified: true,
		},
		{
			// Regression: a revoked/invalid token returns 401 with a body that
			// contains "Unauthorized". It must NOT be treated as verified.
			name:         "401 Unauthorized (revoked token) is unverified",
			statusCode:   401,
			body:         `{"code":"Unauthorized","message":"Unauthorized"}`,
			wantVerified: false,
		},
		{
			name:         "401 with empty body is unverified",
			statusCode:   401,
			body:         ``,
			wantVerified: false,
		},
		{
			name:         "unexpected status code returns verification error",
			statusCode:   404,
			body:         ``,
			wantVerified: false,
			wantErr:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{client: common.ConstantResponseHttpClient(test.statusCode, test.body)}
			data := []byte(fmt.Sprintf("a grafana secret %s here", secret))

			results, err := s.FromData(context.Background(), true, data)
			if err != nil {
				t.Fatalf("FromData() unexpected error = %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}

			if results[0].Verified != test.wantVerified {
				t.Errorf("Verified = %v, want %v", results[0].Verified, test.wantVerified)
			}
			if gotErr := results[0].VerificationError() != nil; gotErr != test.wantErr {
				t.Errorf("verification error present = %v, want %v (err = %v)", gotErr, test.wantErr, results[0].VerificationError())
			}
		})
	}
}
