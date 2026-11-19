package difydataset

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

const testKey = "dataset-t8IMtmhWzulciBpTMRMTqwa4"

// statusServer returns a test server that answers every request with status,
// and a count of the requests it received. It fails the test unless each
// request is a GET to /v1/datasets carrying the key as a Bearer credential.
func statusServer(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/v1/datasets" {
			t.Errorf("unexpected request %s %s, want GET /v1/datasets", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testKey {
			t.Errorf("Authorization = %q, want %q", got, "Bearer "+testKey)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(ts.Close)
	return ts, &hits
}

// fromDataWithEndpoints runs FromData with verification routed only at the
// given endpoints, as an operator-configured scan would.
func fromDataWithEndpoints(t *testing.T, endpoints ...string) detectors.Result {
	t.Helper()
	s := Scanner{}
	require.NoError(t, s.SetConfiguredEndpoints(endpoints...))
	results, err := s.FromData(context.Background(), true, []byte("DIFY_DATASET_KEY="+testKey))
	require.NoError(t, err)
	require.Len(t, results, 1)
	return results[0]
}

func TestDifydataset_VerifyStatuses(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		wantVerified bool
		wantErr      bool
	}{
		{name: "200 verified", status: http.StatusOK, wantVerified: true},
		{name: "401 determinately invalid", status: http.StatusUnauthorized},
		// Dify answers a bad key with 401, so a 403 says nothing certain
		// about the key and must not be reported as a dead key.
		{name: "403 indeterminate", status: http.StatusForbidden, wantErr: true},
		{name: "404 indeterminate", status: http.StatusNotFound, wantErr: true},
		{name: "429 indeterminate", status: http.StatusTooManyRequests, wantErr: true},
		{name: "500 indeterminate", status: http.StatusInternalServerError, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts, _ := statusServer(t, test.status)
			verified, err := verifyMatch(context.Background(), ts.Client(), ts.URL, testKey)
			require.Equal(t, test.wantVerified, verified)
			require.Equal(t, test.wantErr, err != nil, "err = %v", err)
		})
	}
}

func TestDifydataset_DatasetsURL(t *testing.T) {
	for _, base := range []string{
		"https://dify.example.com",
		"https://dify.example.com/",
		"https://dify.example.com/v1",
		"https://dify.example.com/v1/",
	} {
		got, err := datasetsURL(base)
		require.NoError(t, err)
		require.Equal(t, "https://dify.example.com/v1/datasets", got, "base %q", base)
	}
}

func TestDifydataset_SelfHostedKeyVerifies(t *testing.T) {
	// The key is unknown to the first instance (as it would be to Dify Cloud)
	// but valid on the self-hosted one, given with Dify's documented /v1 base.
	cloud, _ := statusServer(t, http.StatusUnauthorized)
	selfHosted, _ := statusServer(t, http.StatusOK)

	got := fromDataWithEndpoints(t, cloud.URL, selfHosted.URL+"/v1")
	require.True(t, got.Verified)
	require.NoError(t, got.VerificationError())
	require.Equal(t, map[string]string{"endpoint": selfHosted.URL + "/v1"}, got.ExtraData)
}

func TestDifydataset_StopsAfterVerified(t *testing.T) {
	first, _ := statusServer(t, http.StatusOK)
	second, secondHits := statusServer(t, http.StatusOK)

	got := fromDataWithEndpoints(t, first.URL, second.URL)
	require.True(t, got.Verified)
	require.Zero(t, secondHits.Load(), "verification must stop at the first instance that accepts the key")
}

func TestDifydataset_EarlierErrorSurvivesLaterMiss(t *testing.T) {
	// A transient failure on one instance must not be erased by a clean 401
	// from another, since the failing instance may be the one that issued it.
	rateLimited, _ := statusServer(t, http.StatusTooManyRequests)
	unknown, _ := statusServer(t, http.StatusUnauthorized)

	got := fromDataWithEndpoints(t, rateLimited.URL, unknown.URL)
	require.False(t, got.Verified)
	require.Error(t, got.VerificationError())
}

func TestDifydataset_AllMissesAreDeterminate(t *testing.T) {
	a, _ := statusServer(t, http.StatusUnauthorized)
	b, _ := statusServer(t, http.StatusUnauthorized)

	got := fromDataWithEndpoints(t, a.URL, b.URL)
	require.False(t, got.Verified)
	require.NoError(t, got.VerificationError())
	require.Nil(t, got.ExtraData)
}

func TestDifydataset_IsFalsePositive(t *testing.T) {
	s := Scanner{}

	// The fixed dataset- prefix contains the word "data", which on its own
	// must not mark a real key as a false positive.
	fp, reason := s.IsFalsePositive(detectors.Result{Raw: []byte(testKey)})
	require.False(t, fp, "real key flagged: %s", reason)

	// A placeholder body is still caught.
	fp, _ = s.IsFalsePositive(detectors.Result{Raw: []byte("dataset-xxxxxxxxxxxxxxxxxxxxxxxx")})
	require.True(t, fp)

	// The default check on the whole key would have discarded the real key.
	fp, _ = detectors.IsKnownFalsePositive(testKey, detectors.DefaultFalsePositives, true)
	require.True(t, fp, "default check no longer flags the prefix; this override may be unnecessary")
}

func TestDifydataset_UsesCloudEndpointByDefault(t *testing.T) {
	// DefaultDetectors() sets the cloud endpoint at startup; mirror that and
	// point it at a test server to check the cloud host is used.
	cloud, hits := statusServer(t, http.StatusOK)
	s := Scanner{}
	s.SetCloudEndpoint(cloud.URL)
	s.UseCloudEndpoint(true)

	results, err := s.FromData(context.Background(), true, []byte(testKey))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.True(t, results[0].Verified)
	require.Equal(t, int32(1), hits.Load())
	require.Equal(t, "https://api.dify.ai", Scanner{}.CloudEndpoint())
}
