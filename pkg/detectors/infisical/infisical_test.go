package infisical

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// A synthetic token in the exact shape Infisical issues:
	// st.<uuid>.<32 lowercase hex>. Not a real credential.
	validToken   = "st.550e8400-e29b-41d4-a716-446655440000.0123456789abcdef0123456789abcdef"
	validPattern = `
		# Infisical configuration
		infisical_token: "st.550e8400-e29b-41d4-a716-446655440000.0123456789abcdef0123456789abcdef"
	`
	// The same token as the Infisical dashboard displays it, with the
	// fourth 32-hex segment the frontend appends. Not a real credential.
	dashboardToken = validToken + ".fedcba9876543210fedcba9876543210"
)

func TestInfisical_Pattern(t *testing.T) {
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
			want:  []string{validToken},
		},
		{
			name:  "valid pattern - dashboard four-part token",
			input: `INFISICAL_TOKEN=` + dashboardToken,
			want:  []string{dashboardToken},
		},
		{
			name:  "invalid pattern - short secret",
			input: `token: "st.550e8400-e29b-41d4-a716-446655440000.0123456789abcdef0123456789abcde"`,
			want:  nil,
		},
		{
			name:  "invalid pattern - not a uuid",
			input: `token: "st.not-a-uuid.0123456789abcdef0123456789abcdef"`,
			want:  nil,
		},
		{
			name:  "invalid pattern - missing prefix",
			input: `token: "550e8400-e29b-41d4-a716-446655440000.0123456789abcdef0123456789abcdef"`,
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
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
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

// statusServer returns an httptest server that replies with status to every
// verification request, and a count of the requests it received. It fails
// the test unless each request is a GET to the Infisical token metadata
// endpoint that carries the three-part token as a Bearer credential.
func statusServer(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/api/v2/service-token" {
			t.Errorf("unexpected request %s %s, want GET /api/v2/service-token", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+validToken {
			t.Errorf("Authorization = %q, want %q", got, "Bearer "+validToken)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
	}))
	return ts, &hits
}

func TestInfisical_VerifyServiceTokenStatuses(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		wantVerified bool
		wantErr      bool
	}{
		{name: "200 verified", status: http.StatusOK, wantVerified: true, wantErr: false},
		{name: "401 determinately invalid", status: http.StatusUnauthorized, wantVerified: false, wantErr: false},
		{name: "404 determinately invalid (unknown token)", status: http.StatusNotFound, wantVerified: false, wantErr: false},
		// Ambiguous or transient statuses must be indeterminate, never a
		// determinate miss: a scoped-but-valid token can draw a 403, and
		// 429/5xx carry no information about the token at all.
		{name: "400 indeterminate", status: http.StatusBadRequest, wantVerified: false, wantErr: true},
		{name: "403 indeterminate", status: http.StatusForbidden, wantVerified: false, wantErr: true},
		{name: "429 indeterminate (rate limited)", status: http.StatusTooManyRequests, wantVerified: false, wantErr: true},
		{name: "500 indeterminate", status: http.StatusInternalServerError, wantVerified: false, wantErr: true},
		{name: "503 indeterminate", status: http.StatusServiceUnavailable, wantVerified: false, wantErr: true},
		{name: "unexpected status indeterminate", status: http.StatusTeapot, wantVerified: false, wantErr: true},
		{name: "204 indeterminate (only 200 verifies)", status: http.StatusNoContent, wantVerified: false, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts, _ := statusServer(t, test.status)
			defer ts.Close()

			verified, err := verifyServiceToken(context.Background(), ts.Client(), ts.URL, validToken)
			if verified != test.wantVerified {
				t.Errorf("verified = %v, want %v", verified, test.wantVerified)
			}
			if (err != nil) != test.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, test.wantErr)
			}
		})
	}
}

// fromDataWithEndpoints runs FromData with verification routed only at the
// given test servers.
func fromDataWithEndpoints(t *testing.T, token string, endpoints ...string) []detectors.Result {
	t.Helper()
	d := Scanner{}
	if err := d.SetConfiguredEndpoints(endpoints...); err != nil {
		t.Fatalf("SetConfiguredEndpoints: %v", err)
	}
	results, err := d.FromData(context.Background(), true, []byte(token))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	return results
}

func TestInfisical_RegionFallback(t *testing.T) {
	// The "wrong region" host does not recognize the token (404), while the
	// token is valid on the second host. Verification must still succeed
	// once the correct host is tried.
	wrongRegion, _ := statusServer(t, http.StatusNotFound)
	defer wrongRegion.Close()
	rightRegion, _ := statusServer(t, http.StatusOK)
	defer rightRegion.Close()

	results := fromDataWithEndpoints(t, validToken, wrongRegion.URL, rightRegion.URL)
	r := results[0]
	if !r.Verified {
		t.Fatalf("expected token to verify after region fallback")
	}
	if r.ExtraData["endpoint"] != rightRegion.URL {
		t.Errorf("expected endpoint %s, got %s", rightRegion.URL, r.ExtraData["endpoint"])
	}
	if r.VerificationError() != nil {
		t.Errorf("expected no verification error after successful verify, got %v", r.VerificationError())
	}
}

func TestInfisical_EarlierErrorSurvivesLaterMiss(t *testing.T) {
	// A transient failure on the first host must not be erased by a clean
	// 404 from the second host, which may simply be the wrong region.
	rateLimited, _ := statusServer(t, http.StatusTooManyRequests)
	defer rateLimited.Close()
	wrongRegion, _ := statusServer(t, http.StatusNotFound)
	defer wrongRegion.Close()

	r := fromDataWithEndpoints(t, validToken, rateLimited.URL, wrongRegion.URL)[0]
	if r.Verified {
		t.Errorf("result should not verify")
	}
	if r.VerificationError() == nil {
		t.Errorf("expected the HTTP 429 verification error to be kept, got nil")
	}
}

func TestInfisical_TransientStatusIsNotDropped(t *testing.T) {
	// 429 and 5xx responses are indeterminate: the result must stay
	// unverified but carry a verification error so tooling does not treat
	// it as a determinate miss.
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusForbidden} {
		t.Run(fmt.Sprintf("status %d", status), func(t *testing.T) {
			ts, _ := statusServer(t, status)
			defer ts.Close()

			r := fromDataWithEndpoints(t, validToken, ts.URL)[0]
			if r.Verified {
				t.Errorf("result should not verify on HTTP %d", status)
			}
			if r.VerificationError() == nil {
				t.Errorf("expected verification error on HTTP %d, got nil", status)
			}
		})
	}
}

func TestInfisical_DeterminateMissHasNoVerificationError(t *testing.T) {
	// 401/404 mean the host genuinely does not recognize the token: no
	// verification error is recorded.
	for _, status := range []int{http.StatusUnauthorized, http.StatusNotFound} {
		t.Run(fmt.Sprintf("status %d", status), func(t *testing.T) {
			ts, _ := statusServer(t, status)
			defer ts.Close()

			r := fromDataWithEndpoints(t, validToken, ts.URL)[0]
			if r.Verified {
				t.Errorf("synthetic token should not verify")
			}
			if r.VerificationError() != nil {
				t.Errorf("expected no verification error on HTTP %d, got %v", status, r.VerificationError())
			}
		})
	}
}

func TestInfisical_400IsIndeterminate(t *testing.T) {
	// The token metadata endpoint takes no parameters, so a 400 does not
	// show that the token authenticated. It is indeterminate, not verified.
	ts, _ := statusServer(t, http.StatusBadRequest)
	defer ts.Close()

	r := fromDataWithEndpoints(t, validToken, ts.URL)[0]
	if r.Verified {
		t.Errorf("result should not verify on HTTP 400")
	}
	if r.VerificationError() == nil {
		t.Errorf("expected verification error on HTTP 400, got nil")
	}
	if r.DetectorType.String() != "Infisical" {
		t.Errorf("expected DetectorType Infisical, got %s", r.DetectorType.String())
	}
}

func TestInfisical_DuplicateDashboardTokenVerifiesOnce(t *testing.T) {
	// The same dashboard token twice in one chunk yields one result that
	// keeps all four segments, and one verification request that sends only
	// the three-part token (statusServer checks the Authorization header).
	ts, hits := statusServer(t, http.StatusOK)
	defer ts.Close()

	r := fromDataWithEndpoints(t, dashboardToken+"\n"+dashboardToken, ts.URL)[0]
	if !r.Verified {
		t.Errorf("expected dashboard token to verify")
	}
	if string(r.Raw) != dashboardToken || r.SecretParts["key"] != dashboardToken {
		t.Errorf("Raw = %q, SecretParts[key] = %q, want %q", r.Raw, r.SecretParts["key"], dashboardToken)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("verification requests = %d, want 1", got)
	}
}
