package gitea

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestGitea_Pattern(t *testing.T) {
	d := Scanner{}
	d.SetCloudEndpoint("https://gitea.com")
	d.UseCloudEndpoint(true)
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - assignment",
			input: `GITEA_TOKEN=4ad5f3b1c9e0d27a6f8b1e2c3d4a5b6c7d8e9f01`,
			want:  []string{"4ad5f3b1c9e0d27a6f8b1e2c3d4a5b6c7d8e9f01https://gitea.com"},
		},
		{
			name:  "valid pattern - quoted",
			input: `gitea_api_token: "0123456789abcdef0123456789abcdef01234567"`,
			want:  []string{"0123456789abcdef0123456789abcdef01234567https://gitea.com"},
		},
		{
			name:  "invalid pattern - no keyword",
			input: `TOKEN=4ad5f3b1c9e0d27a6f8b1e2c3d4a5b6c7d8e9f01`,
			want:  nil,
		},
		{
			name:  "invalid pattern - uppercase hex",
			input: `gitea token = 4AD5F3B1C9E0D27A6F8B1E2C3D4A5B6C7D8E9F01`,
			want:  nil,
		},
		{
			name:  "invalid pattern - wrong length",
			input: `gitea token = 4ad5f3b1c9e0d27a6f8b1e2c3d4a5b6c`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && test.want != nil {
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

// TestGitea_Verification exercises the verification status codes using mock
// HTTP clients, so it requires no live credentials.
func TestGitea_Verification(t *testing.T) {
	const token = "9f3a7c1e0b6d48a25e1f7c93d04b8a6f2c5e9d10"
	input := []byte("gitea token = " + token)

	newScanner := func(client *http.Client) Scanner {
		s := Scanner{client: client}
		s.SetCloudEndpoint("https://gitea.com")
		s.UseCloudEndpoint(true)
		return s
	}

	tests := []struct {
		name                string
		scanner             Scanner
		wantVerified        bool
		wantVerificationErr bool
	}{
		{
			name:         "verified (200)",
			scanner:      newScanner(common.ConstantResponseHttpClient(http.StatusOK, `{"id":1}`)),
			wantVerified: true,
		},
		{
			name:         "unverified - determinate (401)",
			scanner:      newScanner(common.ConstantResponseHttpClient(http.StatusUnauthorized, "")),
			wantVerified: false,
		},
		{
			name:         "unverified - determinate (403)",
			scanner:      newScanner(common.ConstantResponseHttpClient(http.StatusForbidden, "")),
			wantVerified: false,
		},
		{
			name:                "unverified - indeterminate (unexpected response)",
			scanner:             newScanner(common.ConstantResponseHttpClient(http.StatusInternalServerError, "")),
			wantVerified:        false,
			wantVerificationErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results, err := test.scanner.FromData(context.Background(), true, input)
			if err != nil {
				t.Fatalf("FromData() error = %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			r := results[0]
			if r.Verified != test.wantVerified {
				t.Errorf("Verified = %v, want %v", r.Verified, test.wantVerified)
			}
			if (r.VerificationError() != nil) != test.wantVerificationErr {
				t.Errorf("VerificationError = %v, wantVerificationErr %v", r.VerificationError(), test.wantVerificationErr)
			}
		})
	}
}

// TestGitea_Verification_Timeout covers the indeterminate failure caused by a
// network timeout.
func TestGitea_Verification_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s := Scanner{client: common.SaneHttpClientTimeOut(1 * time.Millisecond)}
	if err := s.SetConfiguredEndpoints(server.URL); err != nil {
		t.Fatalf("SetConfiguredEndpoints() error = %v", err)
	}
	s.UseCloudEndpoint(false)
	s.UseFoundEndpoints(false)

	results, err := s.FromData(context.Background(), true, []byte("gitea token = 9f3a7c1e0b6d48a25e1f7c93d04b8a6f2c5e9d10"))
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verified {
		t.Errorf("expected unverified on timeout")
	}
	if results[0].VerificationError() == nil {
		t.Errorf("expected indeterminate verification error on timeout")
	}
}
