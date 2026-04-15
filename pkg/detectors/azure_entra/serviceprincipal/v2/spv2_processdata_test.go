package v2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			clientIDs := map[string]struct{}{clientID: {}}
			tenantIDs := map[string]struct{}{tenantID: {}}

			results := ProcessData(context.Background(), secrets, clientIDs, tenantIDs, true, client)

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
	clientIDs := map[string]struct{}{clientID: {}}
	tenantIDs := map[string]struct{}{tenantID: {}}

	results := ProcessData(context.Background(), secrets, clientIDs, tenantIDs, true, client)

	require.Len(t, results, 1, "expired secret must still produce a result")
	r := results[0]
	assert.False(t, r.Verified, "expired secret should not be marked as verified")
	assert.Equal(t, detector_typepb.DetectorType_Azure, r.DetectorType)
	assert.Equal(t, []byte(clientSecret), r.Raw)
	assert.NotNil(t, r.RawV2, "RawV2 should be set when clientId and tenantId are known")
	assert.Nil(t, r.VerificationError(), "expired secret is definitively invalid, not indeterminate")
}
