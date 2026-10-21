package v2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type mockTransport struct {
	handler http.Handler
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

func newMockAzureClient(tenantID string, tokenStatus int, tokenResponseBody map[string]string) *http.Client {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		openIDPath := fmt.Sprintf("/%s/.well-known/openid-configuration", tenantID)
		tokenPath := fmt.Sprintf("/%s/oauth2/v2.0/token", tenantID)

		switch {
		case r.Method == http.MethodGet && r.URL.Path == openIDPath:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost && r.URL.Path == tokenPath:
			w.WriteHeader(tokenStatus)
			_ = json.NewEncoder(w).Encode(tokenResponseBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return &http.Client{Transport: &mockTransport{handler: handler}}
}

func TestProcessData_VerificationErrors(t *testing.T) {
	const (
		clientSecret = "abc4Q~fake-secret-that-is-long-enough1234567"
		clientID     = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	)

	tests := []struct {
		name            string
		tokenStatus     int
		tokenResponse   map[string]string
		wantResultCount int
		wantVerified    bool
	}{
		{
			name:        "expired secret produces unverified result",
			tokenStatus: http.StatusUnauthorized,
			tokenResponse: map[string]string{
				"error":             "invalid_client",
				"error_description": "AADSTS7000222: The provided client secret keys for app are expired.",
			},
			wantResultCount: 1,
			wantVerified:    false,
		},
		{
			name:        "invalid secret still produces unverified result",
			tokenStatus: http.StatusUnauthorized,
			tokenResponse: map[string]string{
				"error":             "invalid_client",
				"error_description": "AADSTS7000215: Invalid client secret provided.",
			},
			wantResultCount: 1,
			wantVerified:    false,
		},
		{
			name:        "conditional access policy still produces unverified result",
			tokenStatus: http.StatusBadRequest,
			tokenResponse: map[string]string{
				"error":             "access_denied",
				"error_description": "AADSTS53003: Access blocked by Conditional Access policies.",
			},
			wantResultCount: 1,
			wantVerified:    false,
		},
		{
			name:        "verified secret produces verified result",
			tokenStatus: http.StatusOK,
			tokenResponse: map[string]string{
				"access_token": "eyJhbGciOiJub25lIn0.e30.",
			},
			wantResultCount: 1,
			wantVerified:    true,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tenantID := fmt.Sprintf("a1b2c3d4-0000-0000-0000-%012d", i)
			client := newMockAzureClient(tenantID, tc.tokenStatus, tc.tokenResponse)

			secrets := map[string]struct{}{clientSecret: {}}
			clientIDs := map[string][]int{clientID: {0}}
			tenantIDs := map[string][]int{tenantID: {0}}

			results := ProcessData(context.Background(), clientSecret, secrets, clientIDs, tenantIDs, true, client)

			require.Len(t, results, tc.wantResultCount)
			if tc.wantResultCount > 0 {
				r := results[0]
				assert.Equal(t, tc.wantVerified, r.Verified)
				assert.Equal(t, detector_typepb.DetectorType_Azure, r.DetectorType)
				assert.Equal(t, []byte(clientSecret), r.Raw)
				assert.NotNil(t, r.RawV2, "RawV2 should be set when clientId and tenantId are known")
			}
		})
	}
}

func TestProcessData_ExpiredSecretShouldEmitResult(t *testing.T) {
	const (
		clientSecret = "abc4Q~fake-secret-that-is-long-enough1234567"
		clientID     = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
		tenantID     = "f9e8d7c6-0000-0000-0000-ccc000000099"
	)

	client := newMockAzureClient(tenantID, http.StatusUnauthorized, map[string]string{
		"error":             "invalid_client",
		"error_description": "AADSTS7000222: The provided client secret keys for app are expired.",
	})

	secrets := map[string]struct{}{clientSecret: {}}
	clientIDs := map[string][]int{clientID: {0}}
	tenantIDs := map[string][]int{tenantID: {0}}

	results := ProcessData(context.Background(), clientSecret, secrets, clientIDs, tenantIDs, true, client)

	require.Len(t, results, 1, "expired secret must still produce a result")
	r := results[0]
	assert.False(t, r.Verified, "expired secret should not be marked as verified")
	assert.Equal(t, detector_typepb.DetectorType_Azure, r.DetectorType)
	assert.Equal(t, []byte(clientSecret), r.Raw)
	assert.NotNil(t, r.RawV2, "RawV2 should be set when clientId and tenantId are known")
	assert.Nil(t, r.VerificationError(), "expired secret is definitively invalid, not indeterminate")
}

// Two secrets, each with its own client and tenant. Rotated (verify off) and live
// secrets must report the same nearest pair, so the result keeps one identity.
func TestProcessData_NearestClientAndTenantWins(t *testing.T) {
	const (
		secretA = "abc4Q~fake-secret-that-is-long-enough1234567"
		secretB = "xyz4Q~another-fake-secret-long-enough7654321"
		clientA = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
		tenantA = "f9e8d7c6-1111-2222-3333-ccc000000099"
		clientB = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
		tenantB = "e8d7c6b5-4444-5555-6666-ddd000000088"
	)
	data := "client_id=" + clientA + "\ntenant_id=" + tenantA + "\nsecret=" + secretA + "\n" +
		strings.Repeat("filler\n", 50) +
		"client_id=" + clientB + "\ntenant_id=" + tenantB + "\nsecret=" + secretB + "\n"

	clientIDs := map[string][]int{
		clientA: {strings.Index(data, clientA)},
		clientB: {strings.Index(data, clientB)},
	}
	tenantIDs := map[string][]int{
		tenantA: {strings.Index(data, tenantA)},
		tenantB: {strings.Index(data, tenantB)},
	}
	secrets := map[string]struct{}{secretA: {}, secretB: {}}

	results := ProcessData(context.Background(), data, secrets, clientIDs, tenantIDs, false, nil)

	require.Len(t, results, 2)
	for _, r := range results {
		var want string
		switch string(r.Raw) {
		case secretA:
			want = fmt.Sprintf(`{"clientSecret":"%s","clientId":"%s","tenantId":"%s"}`, secretA, clientA, tenantA)
		case secretB:
			want = fmt.Sprintf(`{"clientSecret":"%s","clientId":"%s","tenantId":"%s"}`, secretB, clientB, tenantB)
		}
		assert.Equal(t, want, string(r.RawV2))
	}
}

// roundTripFunc lets a test script the HTTP responses directly.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func tokenErrorResponse(status int, description string) *http.Response {
	rec := httptest.NewRecorder()
	rec.WriteHeader(status)
	_ = json.NewEncoder(rec).Encode(map[string]string{"error": "invalid_client", "error_description": description})
	return rec.Result()
}

// An unrelated client sits closer to the secret than the real one. Once the unrelated
// client is ruled out, the live and the rotated secret must report the same client.
func TestProcessData_RotatedSecretKeepsClientThatVerified(t *testing.T) {
	const (
		secret   = "abc4Q~fake-secret-that-is-long-enough1234567"
		otherApp = "1474bfe8-663c-486e-9daf-f1f580302218"
		realApp  = "8595f61a-109a-497d-8c8f-566b733e95fe"
		tenant   = "7a1c2b3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	)
	data := "client_id: " + otherApp + "\nsecret: " + secret + "\n" + strings.Repeat("filler\n", 20) + "client_id: " + realApp + "\n"

	run := func(realAppStatus int, realAppDescription string) detectors.Result {
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodGet {
				return tokenErrorResponse(http.StatusOK, ""), nil
			}
			_ = r.ParseForm()
			switch {
			case r.PostForm.Get("client_id") == otherApp:
				return tokenErrorResponse(http.StatusBadRequest, "AADSTS700016: app not found"), nil
			case realAppStatus == http.StatusOK:
				rec := httptest.NewRecorder()
				_ = json.NewEncoder(rec).Encode(map[string]string{"access_token": "x"})
				return rec.Result(), nil
			default:
				return tokenErrorResponse(realAppStatus, realAppDescription), nil
			}
		})}
		clientIDs := map[string][]int{otherApp: {strings.Index(data, otherApp)}, realApp: {strings.Index(data, realApp)}}
		tenantIDs := map[string][]int{tenant: {0}}
		results := ProcessData(context.Background(), data, map[string]struct{}{secret: {}}, clientIDs, tenantIDs, true, client)
		require.Len(t, results, 1)
		return results[0]
	}

	live := run(http.StatusOK, "")
	rotated := run(http.StatusUnauthorized, "AADSTS7000215: Invalid client secret provided.")

	assert.True(t, live.Verified)
	assert.False(t, rotated.Verified)
	assert.Contains(t, string(live.RawV2), realApp)
	assert.Equal(t, string(live.RawV2), string(rotated.RawV2))
}

// Without verification nothing removes a tenant ID that also looked like a client ID,
// so the fallback must not report it as both.
func TestProcessData_ClientIsNeverTheTenant(t *testing.T) {
	const (
		secret = "abc4Q~fake-secret-that-is-long-enough1234567"
		tenant = "608e4ac4-2ca8-40dd-a046-4064540a1cde"
		app    = "8595f61a-109a-497d-8c8f-566b733e95fe"
	)
	data := secret + " " + tenant + " " + app
	clientIDs := map[string][]int{tenant: {len(secret) + 1}, app: {1000}}
	tenantIDs := map[string][]int{tenant: {len(secret) + 1}}

	results := ProcessData(context.Background(), data, map[string]struct{}{secret: {}}, clientIDs, tenantIDs, false, nil)

	require.Len(t, results, 1)
	assert.JSONEq(t, fmt.Sprintf(`{"clientSecret":%q,"clientId":%q,"tenantId":%q}`, secret, app, tenant), string(results[0].RawV2))
}

// A failed tenant lookup is "unknown", not "missing". The nearest tenant must stay
// the reported one even though it couldn't be checked.
func TestProcessData_TransientTenantErrorKeepsNearestTenant(t *testing.T) {
	const (
		secret     = "abc4Q~fake-secret-that-is-long-enough1234567"
		app        = "8595f61a-109a-497d-8c8f-566b733e95fe"
		nearTenant = "3b1f0c2e-9d4a-4c6b-a7e8-5f2d1c0b9a87"
		farTenant  = "c4d5e6f7-1a2b-4c3d-9e8f-0a1b2c3d4e5f"
	)
	data := "tenant_id: " + nearTenant + "\nsecret: " + secret + "\n" + strings.Repeat("filler\n", 20) + "tenant_id: " + farTenant + "\n"
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			if strings.Contains(r.URL.Path, nearTenant) {
				return nil, errors.New("network down")
			}
			return tokenErrorResponse(http.StatusOK, ""), nil
		}
		// The app isn't found in the tenant that could be checked, so nothing is learned.
		return tokenErrorResponse(http.StatusBadRequest, "AADSTS700016: app not found"), nil
	})}
	clientIDs := map[string][]int{app: {0}}
	tenantIDs := map[string][]int{nearTenant: {strings.Index(data, nearTenant)}, farTenant: {strings.Index(data, farTenant)}}

	results := ProcessData(context.Background(), data, map[string]struct{}{secret: {}}, clientIDs, tenantIDs, true, client)

	require.Len(t, results, 1)
	assert.Contains(t, string(results[0].RawV2), nearTenant)
}

// An unrelated tenant sits closer to the secret than the real one. A rotated secret is
// still recognised by the real tenant (secret invalid, not app missing), so the result
// must match the live one.
func TestProcessData_RotatedSecretKeepsTenantThatRecognisedTheApp(t *testing.T) {
	const (
		secret      = "abc4Q~fake-secret-that-is-long-enough1234567"
		app         = "8595f61a-109a-497d-8c8f-566b733e95fe"
		otherTenant = "d1e2f3a4-5b6c-4d7e-8f90-a1b2c3d4e5f6"
		realTenant  = "e7f8a9b0-2c3d-4e5f-9a1b-6c7d8e9f0a1b"
	)
	data := "tenant_id: " + otherTenant + "\nsecret: " + secret + "\n" + strings.Repeat("filler\n", 20) + "tenant_id: " + realTenant + "\n"

	run := func(live bool) detectors.Result {
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodGet {
				return tokenErrorResponse(http.StatusOK, ""), nil
			}
			switch {
			case strings.Contains(r.URL.Path, otherTenant):
				return tokenErrorResponse(http.StatusBadRequest, "AADSTS700016: app not found"), nil
			case live:
				rec := httptest.NewRecorder()
				_ = json.NewEncoder(rec).Encode(map[string]string{"access_token": "x"})
				return rec.Result(), nil
			default:
				return tokenErrorResponse(http.StatusUnauthorized, "AADSTS7000215: Invalid client secret provided."), nil
			}
		})}
		clientIDs := map[string][]int{app: {0}}
		tenantIDs := map[string][]int{otherTenant: {strings.Index(data, otherTenant)}, realTenant: {strings.Index(data, realTenant)}}
		results := ProcessData(context.Background(), data, map[string]struct{}{secret: {}}, clientIDs, tenantIDs, true, client)
		require.Len(t, results, 1)
		return results[0]
	}

	live := run(true)
	rotated := run(false)

	assert.True(t, live.Verified)
	assert.False(t, rotated.Verified)
	assert.Contains(t, string(live.RawV2), realTenant)
	assert.Equal(t, string(live.RawV2), string(rotated.RawV2))
}

// A tenant lookup that keeps failing must be tried once, not once per secret and client.
func TestProcessData_FailedTenantLookupIsNotRepeated(t *testing.T) {
	const (
		tenant  = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
		clientA = "8595f61a-109a-497d-8c8f-566b733e95fe"
		clientB = "d2c1b0a9-8f7e-4d6c-b5a4-3f2e1d0c9b8a"
	)
	secrets := map[string]struct{}{
		"abc4Q~fake-secret-that-is-long-enough1234567": {},
		"xyz9Q~another-fake-secret-long-enough7654321": {},
	}
	data := "tenant_id: " + tenant + "\n"
	lookups := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		lookups++
		return tokenErrorResponse(http.StatusTooManyRequests, ""), nil
	})}
	clientIDs := map[string][]int{clientA: {0}, clientB: {1}}
	tenantIDs := map[string][]int{tenant: {len("tenant_id: ")}}

	results := ProcessData(context.Background(), data, secrets, clientIDs, tenantIDs, true, client)

	assert.Len(t, results, 2)
	assert.Equal(t, 1, lookups)
}
