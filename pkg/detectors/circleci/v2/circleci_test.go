package circleci

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

const validToken = "CCIPAT_FAKEd5qPreGFAKEaQxBi6i_914bf0042f4f2d34e1d2ef6615c051a5caf70172"

var _ detectors.EndpointCustomizer = (*Scanner)(nil)

func TestCircleCI_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
				# Configuration File: config.yaml
				database:
					host: $DB_HOST
					port: $DB_PORT
					username: $DB_USERNAME
					password: $DB_PASS  # IMPORTANT: Do not share this password publicly

				api:
					auth_type: API-Key
					base_url: "https://api.example.com/v1/user"
					api_key: "CCIPAT_FAKEd5qPreGFAKEaQxBi6i_914bf0042f4f2d34e1d2ef6615c051a5caf70172"

				# Notes:
				# - Remember to rotate the secret every 90 days.
				# - The above credentials should only be used in a secure environment.
			`,
			want: []string{validToken},
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

func TestCircleCI_VerifiesAgainstConfiguredEndpoint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/me" {
			t.Errorf("path = %q, want /api/v2/me", r.URL.Path)
		}
		if got := r.Header.Get("Circle-Token"); got != validToken {
			t.Errorf("Circle-Token = %q, want %q", got, validToken)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := Scanner{client: server.Client()}
	if err := d.SetConfiguredEndpoints(server.URL); err != nil {
		t.Fatalf("SetConfiguredEndpoints() error = %v", err)
	}
	d.UseCloudEndpoint(false)

	results, err := d.FromData(context.Background(), true, []byte(`circleci api_key: "`+validToken+`"`))
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if !results[0].Verified {
		t.Fatalf("Verified = false, want true")
	}
	if err := results[0].VerificationError(); err != nil {
		t.Fatalf("VerificationError() = %v, want nil", err)
	}
}

func TestCircleCI_Unauthorized(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	d := Scanner{client: server.Client()}
	if err := d.SetConfiguredEndpoints(server.URL); err != nil {
		t.Fatalf("SetConfiguredEndpoints() error = %v", err)
	}
	d.UseCloudEndpoint(false)

	results, err := d.FromData(context.Background(), true, []byte(`circleci api_key: "`+validToken+`"`))
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].Verified {
		t.Fatalf("Verified = true, want false")
	}
	if err := results[0].VerificationError(); err != nil {
		t.Fatalf("VerificationError() = %v, want nil", err)
	}
}

func TestCircleCI_VerifiesAgainstLaterConfiguredEndpoint(t *testing.T) {
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errorServer.Close()

	verifiedServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer verifiedServer.Close()

	d := Scanner{client: verifiedServer.Client()}
	if err := d.SetConfiguredEndpoints(errorServer.URL, verifiedServer.URL); err != nil {
		t.Fatalf("SetConfiguredEndpoints() error = %v", err)
	}
	d.UseCloudEndpoint(false)

	results, err := d.FromData(context.Background(), true, []byte(`circleci api_key: "`+validToken+`"`))
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if !results[0].Verified {
		t.Fatalf("Verified = false, want true")
	}
	if err := results[0].VerificationError(); err != nil {
		t.Fatalf("VerificationError() = %v, want nil", err)
	}
}

func TestCircleCI_PreservesEndpointErrorWhenLaterEndpointUnauthorized(t *testing.T) {
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errorServer.Close()

	unauthorizedServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer unauthorizedServer.Close()

	d := Scanner{client: unauthorizedServer.Client()}
	if err := d.SetConfiguredEndpoints(errorServer.URL, unauthorizedServer.URL); err != nil {
		t.Fatalf("SetConfiguredEndpoints() error = %v", err)
	}
	d.UseCloudEndpoint(false)

	results, err := d.FromData(context.Background(), true, []byte(`circleci api_key: "`+validToken+`"`))
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].Verified {
		t.Fatalf("Verified = true, want false")
	}
	verificationErr := results[0].VerificationError()
	if verificationErr == nil {
		t.Fatalf("VerificationError() = nil, want endpoint error")
	}
	if !strings.Contains(verificationErr.Error(), "unexpected status code: 500") {
		t.Fatalf("VerificationError() = %v, want status code 500 error", verificationErr)
	}
}

func TestCircleCI_DefaultsToCloudEndpoint(t *testing.T) {
	if got := (Scanner{}).CloudEndpoint(); got != "https://circleci.com" {
		t.Fatalf("CloudEndpoint() = %q, want https://circleci.com", got)
	}
}
