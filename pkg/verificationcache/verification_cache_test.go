package verificationcache

import (
	"context"
	"errors"
	"testing"
	"time"

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
		copy := detectors.Result{Redacted: r.Redacted, Raw: r.Raw, RawV2: r.RawV2, DetectorType: r.DetectorType}
		if verify {
			copy.CopyVerificationInfo(&r)
		}
		results = append(results, copy)
	}

	// The metric timing resolution is 1 ms, so the detector needs to artificially slow down so that it can actually be
	// monitored.
	time.Sleep(2 * time.Millisecond)

	return results, nil
}

func (t *testDetector) Keywords() []string             { return nil }
func (t *testDetector) Type() detectorspb.DetectorType { return -1 }
func (t *testDetector) Description() string            { return "" }

var _ detectors.Detector = (*testDetector)(nil)

func getResultCacheKey(t *testing.T, cache *VerificationCache, result detectors.Result) string {
	key, err := cache.getResultCacheKey(result)
	require.NoError(t, err)
	return string(key)
}

func TestVerificationCache_FromData_Passthrough(t *testing.T) {
	detector := testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
	}}

	require.NotPanics(t, func() {
		cache := New(nil, nil)
		results, err := cache.FromData(
			logContext.Background(),
			&detector,
			true,
			true,
			nil)

		require.NoError(t, err)
		assert.Equal(t, 1, detector.fromDataCallCount)
		assert.ElementsMatch(t, detector.results, results)
	})
}

func TestVerificationCache_FromData_VerifyFalseForceCacheUpdateFalse(t *testing.T) {
	detector := testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
	}}
	metrics := InMemoryMetrics{}
	cache := New(simple.NewCache[detectors.Result](), &metrics)

	results, err := cache.FromData(
		logContext.Background(),
		&detector,
		false,
		false,
		nil)

	require.NoError(t, err)
	assert.Equal(t, 1, detector.fromDataCallCount)
	assert.ElementsMatch(t, []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: false},
	}, results)
	assert.Empty(t, cache.resultCache.Values())
	assert.Equal(t, int64(0), metrics.FromDataVerifyTimeSpentMS.Load())
	assert.Equal(t, int32(0), metrics.CredentialVerificationsSaved.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHits.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHitsWasted.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheMisses.Load())
}

func TestVerificationCache_FromData_VerifyFalseForceCacheUpdateTrue(t *testing.T) {
	detector := testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
		{Redacted: "world", Raw: []byte("world"), RawV2: []byte("worldV2"), Verified: false},
	}}
	detector.results[1].SetVerificationError(errors.New("test verification error"))
	metrics := InMemoryMetrics{}
	cache := New(simple.NewCache[detectors.Result](), &metrics)

	results, err := cache.FromData(
		logContext.Background(),
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
	assert.ElementsMatch(t, []detectors.Result{
		{Redacted: "hello", Verified: false},
		{Redacted: "world", Verified: false},
	}, cache.resultCache.Values())
	assert.Equal(t, int64(0), metrics.FromDataVerifyTimeSpentMS.Load())
	assert.Equal(t, int32(0), metrics.CredentialVerificationsSaved.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHits.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHitsWasted.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheMisses.Load())
}

func TestVerificationCache_FromData_VerifyTrueForceCacheUpdateFalseAllCacheHits(t *testing.T) {
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
	metrics := InMemoryMetrics{}
	cache := New(simple.NewCache[detectors.Result](), &metrics)
	cache.resultCache.Set(getResultCacheKey(t, cache, remoteResults[0]), cacheData[0])
	cache.resultCache.Set(getResultCacheKey(t, cache, remoteResults[1]), cacheData[1])

	results, err := cache.FromData(
		logContext.Background(),
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
	assert.ElementsMatch(t, cacheData, cache.resultCache.Values())
	assert.Equal(t, int64(0), metrics.FromDataVerifyTimeSpentMS.Load())
	assert.Equal(t, int32(2), metrics.CredentialVerificationsSaved.Load())
	assert.Equal(t, int32(2), metrics.ResultCacheHits.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHitsWasted.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheMisses.Load())
}

func TestVerificationCache_FromData_VerifyTrueForceCacheUpdateFalseCacheMiss(t *testing.T) {
	detector := testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
		{Redacted: "world", Raw: []byte("world"), RawV2: []byte("worldV2"), Verified: false},
	}}
	detector.results[1].SetVerificationError(errors.New("test verification error"))
	cachedResult := detectors.Result{Redacted: "hello", Verified: false}
	cachedResult.SetVerificationError(errors.New("test verification error"))
	resultCache := simple.NewCache[detectors.Result]()
	metrics := InMemoryMetrics{}
	cache := New(resultCache, &metrics)
	cache.resultCache.Set(getResultCacheKey(t, cache, detector.results[0]), cachedResult)

	results, err := cache.FromData(
		logContext.Background(),
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
	assert.ElementsMatch(t, wantCacheData, cache.resultCache.Values())
	assert.Less(t, int64(0), metrics.FromDataVerifyTimeSpentMS.Load())
	assert.Equal(t, int32(0), metrics.CredentialVerificationsSaved.Load())
	assert.Equal(t, int32(1), metrics.ResultCacheHits.Load())
	assert.Equal(t, int32(1), metrics.ResultCacheMisses.Load())
	assert.Equal(t, int32(1), metrics.ResultCacheHitsWasted.Load())
}

func TestVerificationCache_FromData_VerifyTrueForceCacheUpdateTrue(t *testing.T) {
	detector := testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
		{Redacted: "world", Raw: []byte("world"), RawV2: []byte("worldV2"), Verified: false},
	}}
	detector.results[1].SetVerificationError(errors.New("test verification error"))
	metrics := InMemoryMetrics{}
	cache := New(simple.NewCache[detectors.Result](), &metrics)
	cache.resultCache.Set(getResultCacheKey(t, cache, detector.results[0]), detectors.Result{Redacted: "hello", Verified: false})
	cache.resultCache.Set(getResultCacheKey(t, cache, detector.results[1]), detectors.Result{Redacted: "world", Verified: true})

	results, err := cache.FromData(
		logContext.Background(),
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
	assert.ElementsMatch(t, wantCacheData, cache.resultCache.Values())
	assert.Less(t, int64(0), metrics.FromDataVerifyTimeSpentMS.Load())
	assert.Equal(t, int32(0), metrics.CredentialVerificationsSaved.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHits.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheMisses.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHitsWasted.Load())
}

func TestVerificationCache_FromData_SameRawDifferentType_CacheMiss(t *testing.T) {
	detector1 := testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), Verified: true, DetectorType: -1},
	}}
	detector2 := testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), Verified: true, DetectorType: -2},
	}}
	cache := New(simple.NewCache[detectors.Result](), nil)
	_, err := cache.FromData(logContext.Background(), &detector1, true, false, nil)
	require.NoError(t, err)

	res, err := cache.FromData(logContext.Background(), &detector2, true, false, nil)

	if assert.NoError(t, err) {
		if assert.Len(t, res, 1) {
			assert.Equal(t, detectorspb.DetectorType(-2), res[0].DetectorType)
		}
	}
	assert.Len(t, cache.resultCache.Values(), 2)
}

func TestVerificationCache_FromData_SameRawV2DifferentType_CacheMiss(t *testing.T) {
	detector1 := testDetector{results: []detectors.Result{
		{Redacted: "hello", RawV2: []byte("there"), Verified: true, DetectorType: -1},
	}}
	detector2 := testDetector{results: []detectors.Result{
		{Redacted: "hello", RawV2: []byte("there"), Verified: true, DetectorType: -2},
	}}
	cache := New(simple.NewCache[detectors.Result](), nil)
	_, err := cache.FromData(logContext.Background(), &detector1, true, false, nil)
	require.NoError(t, err)

	res, err := cache.FromData(logContext.Background(), &detector2, true, false, nil)

	if assert.NoError(t, err) {
		if assert.Len(t, res, 1) {
			assert.Equal(t, detectorspb.DetectorType(-2), res[0].DetectorType)
		}
	}
	assert.Len(t, cache.resultCache.Values(), 2)
}
