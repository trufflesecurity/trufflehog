package v2

import (
	"context"
	"io"
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProcessData_RawV2DependsOnIDCount shows that the same Azure client
// secret produces different RawV2 values depending on how many candidate
// client/tenant IDs appear in the chunk.
//
// With verify=false, ProcessData populates RawV2 only when there is exactly
// one client ID and exactly one tenant ID. If either set is ambiguous (>1),
// the IDs are cleared and RawV2 is nil.
//
// This is the root cause of CSM-1857's secondary issue: the same logical
// secret can get different hash_v2 values across scans if the surrounding
// chunk context changes, producing duplicate secret rows in the database.
func TestProcessData_RawV2DependsOnIDCount(t *testing.T) {
	const (
		clientSecret = "abc4Q~fake-secret-that-is-long-enough1234567"
		clientID1    = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
		clientID2    = "f9e8d7c6-b5a4-3210-fedc-ba9876543210"
		tenantID1    = "11111111-2222-3333-4444-555566667777"
		tenantID2    = "aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000"
	)

	tests := []struct {
		name      string
		clientIDs map[string]struct{}
		tenantIDs map[string]struct{}
		wantRawV2 bool
	}{
		{
			name:      "single client and tenant",
			clientIDs: map[string]struct{}{clientID1: {}},
			tenantIDs: map[string]struct{}{tenantID1: {}},
			wantRawV2: true,
		},
		{
			name:      "multiple clients clears IDs",
			clientIDs: map[string]struct{}{clientID1: {}, clientID2: {}},
			tenantIDs: map[string]struct{}{tenantID1: {}},
			wantRawV2: false,
		},
		{
			name:      "multiple tenants clears IDs",
			clientIDs: map[string]struct{}{clientID1: {}},
			tenantIDs: map[string]struct{}{tenantID1: {}, tenantID2: {}},
			wantRawV2: false,
		},
		{
			name:      "multiple clients and tenants clears IDs",
			clientIDs: map[string]struct{}{clientID1: {}, clientID2: {}},
			tenantIDs: map[string]struct{}{tenantID1: {}, tenantID2: {}},
			wantRawV2: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secrets := map[string]struct{}{clientSecret: {}}
			results := ProcessData(context.Background(), secrets, tc.clientIDs, tc.tenantIDs, false, nil)

			require.Len(t, results, 1)
			assert.Equal(t, []byte(clientSecret), results[0].Raw, "Raw should always be the client secret")

			if tc.wantRawV2 {
				assert.NotNil(t, results[0].RawV2, "RawV2 should be populated with unambiguous IDs")
			} else {
				assert.Nil(t, results[0].RawV2, "RawV2 should be nil when IDs are ambiguous")
			}
		})
	}
}

// TestProcessData_DeterministicRawV2 verifies that ProcessData produces
// identical RawV2 on repeated calls with the same inputs. Before the sorted
// iteration fix, Go map randomization could cause different (clientId, tenantId)
// pairings across runs.
func TestProcessData_DeterministicRawV2(t *testing.T) {
	const (
		clientSecret = "abc4Q~fake-secret-that-is-long-enough1234567"
		clientID     = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
		tenantID     = "11111111-2222-3333-4444-555566667777"
	)

	var firstRawV2 []byte
	for i := 0; i < 50; i++ {
		results := ProcessData(
			context.Background(),
			map[string]struct{}{clientSecret: {}},
			map[string]struct{}{clientID: {}},
			map[string]struct{}{tenantID: {}},
			false, nil,
		)
		require.Len(t, results, 1)
		if i == 0 {
			firstRawV2 = results[0].RawV2
			require.NotNil(t, firstRawV2)
		} else {
			assert.Equal(t, firstRawV2, results[0].RawV2,
				"RawV2 must be identical across repeated calls (iteration %d)", i)
		}
	}
}

// TestProcessData_DoesNotMutateCallerMaps verifies that ProcessData does not
// modify the maps passed by the caller. It uses verify=true with a mock HTTP
// client so that the verification code path (which contains delete calls) is
// actually exercised. With verify=false, no deletes occur and the test would
// pass trivially even without maps.Clone.
func TestProcessData_DoesNotMutateCallerMaps(t *testing.T) {
	const clientSecret = "abc4Q~fake-secret-that-is-long-enough1234567"

	secrets := map[string]struct{}{clientSecret: {}}
	clientIDs := map[string]struct{}{
		"a1b2c3d4-e5f6-7890-abcd-ef1234567890": {},
		"f9e8d7c6-b5a4-3210-fedc-ba9876543210": {},
	}
	// Use tenant IDs unique to this test to avoid polluting the package-level
	// tenantCache shared with other tests.
	tenantIDs := map[string]struct{}{
		"cccccccc-dddd-eeee-ffff-000011112222": {},
		"dddddddd-eeee-ffff-0000-111122223333": {},
	}

	origSecrets := maps.Clone(secrets)
	origClientIDs := maps.Clone(clientIDs)
	origTenantIDs := maps.Clone(tenantIDs)

	// Return 400 for every request so TenantExists returns false, triggering
	// delete(activeTenants, tenantId) inside the verify block.
	mockClient := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}),
	}

	_ = ProcessData(context.Background(), secrets, clientIDs, tenantIDs, true, mockClient)

	assert.Equal(t, origSecrets, secrets, "caller's secrets map must not be mutated")
	assert.Equal(t, origClientIDs, clientIDs, "caller's clientIDs map must not be mutated")
	assert.Equal(t, origTenantIDs, tenantIDs, "caller's tenantIDs map must not be mutated")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// TestProcessData_SameSecretDifferentRawV2 demonstrates the chain:
// the same client secret scanned with different chunk contexts produces
// different RawV2 bytes depending on whether IDs are ambiguous.
func TestProcessData_SameSecretDifferentRawV2(t *testing.T) {
	const (
		clientSecret = "abc4Q~fake-secret-that-is-long-enough1234567"
		clientID     = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
		tenantID     = "11111111-2222-3333-4444-555566667777"
	)

	// Scan 1: chunk has exactly one client ID and one tenant ID.
	results1 := ProcessData(
		context.Background(),
		map[string]struct{}{clientSecret: {}},
		map[string]struct{}{clientID: {}},
		map[string]struct{}{tenantID: {}},
		false, nil,
	)
	require.Len(t, results1, 1)
	rawV2Populated := results1[0].RawV2
	require.NotNil(t, rawV2Populated, "scan 1: RawV2 should be populated")

	// Scan 2: same secret, but chunk now contains an extra client-like UUID.
	results2 := ProcessData(
		context.Background(),
		map[string]struct{}{clientSecret: {}},
		map[string]struct{}{clientID: {}, "f9e8d7c6-b5a4-3210-fedc-ba9876543210": {}},
		map[string]struct{}{tenantID: {}},
		false, nil,
	)
	require.Len(t, results2, 1)
	rawV2Nil := results2[0].RawV2
	assert.Nil(t, rawV2Nil, "scan 2: RawV2 should be nil due to ambiguous client IDs")

	assert.NotEqual(t, rawV2Populated, rawV2Nil,
		"same logical secret produces different RawV2 depending on chunk context")
}
