package verificationcaching

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type testDetector struct {
	fromDataCallCount int
	results           []detectors.Result
}

func (t *testDetector) FromData(_ context.Context, verify bool, _ []byte) ([]detectors.Result, error) {
	t.fromDataCallCount = t.fromDataCallCount + 1
	var results []detectors.Result
	for _, r := range t.results {
		copy := detectors.Result{Redacted: r.Redacted, Raw: r.Raw, RawV2: r.RawV2}
		if verify {
			copy.CopyVerificationInfo(&r)
		}
		results = append(results, copy)
	}
	return results, nil
}

func (t *testDetector) Keywords() []string             { return nil }
func (t *testDetector) Type() detectorspb.DetectorType { return -1 }
func (t *testDetector) Description() string            { return "" }

var _ detectors.Detector = (*testDetector)(nil)

func getCacheKey(result *detectors.Result) string {
	return string(result.Raw)
}

func TestFromDataCached_NilCache(t *testing.T) {
	detector := testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
	}}

	require.NotPanics(t, func() {
		results, err := FromDataCached(
			logContext.Background(),
			nil,
			func(result *detectors.Result) string { panic("shouldn't happen") },
			&detector,
			true,
			true,
			nil)

		require.NoError(t, err)
		assert.Equal(t, 1, detector.fromDataCallCount)
		assert.ElementsMatch(t, detector.results, results)
	})
}

func TestFromDataCached_VerifyFalseForceCacheUpdateFalse(t *testing.T) {
	detector := testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
	}}
	cache := simple.NewCache[detectors.Result]()

	results, err := FromDataCached(
		logContext.Background(),
		cache,
		getCacheKey,
		&detector,
		false,
		false,
		nil)

	require.NoError(t, err)
	assert.Equal(t, 1, detector.fromDataCallCount)
	assert.ElementsMatch(t, []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: false},
	}, results)
	assert.Empty(t, cache.Values())
}

func TestFromDataCached_VerifyFalseForceCacheUpdateTrue(t *testing.T) {
	detector := testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
		{Redacted: "world", Raw: []byte("world"), RawV2: []byte("worldV2"), Verified: false},
	}}
	detector.results[1].SetVerificationError(errors.New("test verification error"))
	cache := simple.NewCache[detectors.Result]()

	results, err := FromDataCached(
		logContext.Background(),
		cache,
		getCacheKey,
		&detector,
		false,
		true,
		nil)

	require.NoError(t, err)
	assert.Equal(t, 1, detector.fromDataCallCount)
	assert.ElementsMatch(t, []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: false},
		{Redacted: "world", Raw: []byte("world"), RawV2: []byte("worldV2"), Verified: false},
	}, results)
	assert.ElementsMatch(t, []detectors.Result{{Redacted: "hello"}, {Redacted: "world"}}, cache.Values())
}

func TestFromDataCached_VerifyTrueForceCacheUpdateFalseAllCacheHits(t *testing.T) {
	remoteResults := []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
		{Redacted: "world", Raw: []byte("world"), RawV2: []byte("worldV2"), Verified: false},
	}
	remoteResults[1].SetVerificationError(errors.New("test verification error"))
	detector := testDetector{results: remoteResults}
	cacheData := []detectors.Result{
		{Redacted: "hello", Verified: false},
		{Redacted: "world", Verified: true},
	}
	cacheData[0].SetVerificationError(errors.New("test verification error"))
	cache := simple.NewCache[detectors.Result]()
	cache.Set("hello", cacheData[0])
	cache.Set("world", cacheData[1])

	results, err := FromDataCached(
		logContext.Background(),
		cache,
		getCacheKey,
		&detector,
		true,
		false,
		nil)

	require.NoError(t, err)
	assert.Equal(t, 1, detector.fromDataCallCount)
	wantResults := []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: false, VerificationFromCache: true},
		{Redacted: "world", Raw: []byte("world"), RawV2: []byte("worldV2"), Verified: true, VerificationFromCache: true},
	}
	wantResults[0].SetVerificationError(errors.New("test verification error"))
	assert.ElementsMatch(t, wantResults, results)
	assert.ElementsMatch(t, cacheData, cache.Values())
}

func TestFromDataCached_VerifyTrueForceCacheUpdateFalseCacheMiss(t *testing.T) {
	detector := testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
		{Redacted: "world", Raw: []byte("world"), RawV2: []byte("worldV2"), Verified: false},
	}}
	detector.results[1].SetVerificationError(errors.New("test verification error"))
	cacheData := []detectors.Result{
		{Redacted: "hello", Verified: false},
	}
	cacheData[0].SetVerificationError(errors.New("test verification error"))
	cache := simple.NewCacheWithData([]simple.CacheEntry[detectors.Result]{{Key: "hello", Value: cacheData[0]}})

	results, err := FromDataCached(
		logContext.Background(),
		cache,
		getCacheKey,
		&detector,
		true,
		false,
		nil)

	require.NoError(t, err)
	assert.Equal(t, 2, detector.fromDataCallCount)
	assert.ElementsMatch(t, detector.results, results)
	wantCacheData := []detectors.Result{
		{Redacted: "hello", Verified: true},
		{Redacted: "world", Verified: false},
	}
	wantCacheData[1].SetVerificationError(errors.New("test verification error"))
	assert.ElementsMatch(t, wantCacheData, cache.Values())
}

func TestFromDataCached_VerifyTrueForceCacheUpdateTrue(t *testing.T) {
	detector := testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
		{Redacted: "world", Raw: []byte("world"), RawV2: []byte("worldV2"), Verified: false},
	}}
	detector.results[1].SetVerificationError(errors.New("test verification error"))
	cache := simple.NewCache[detectors.Result]()
	cache.Set("hello", detectors.Result{Redacted: "hello", Verified: false})
	cache.Set("world", detectors.Result{Redacted: "world", Verified: true})

	results, err := FromDataCached(
		logContext.Background(),
		cache,
		getCacheKey,
		&detector,
		true,
		true,
		nil)

	require.NoError(t, err)
	assert.Equal(t, 1, detector.fromDataCallCount)
	assert.ElementsMatch(t, detector.results, results)
	wantCacheData := []detectors.Result{
		{Redacted: "hello", Verified: true},
		{Redacted: "world", Verified: false},
	}
	wantCacheData[1].SetVerificationError(errors.New("test verification error"))
	assert.ElementsMatch(t, wantCacheData, cache.Values())
}
