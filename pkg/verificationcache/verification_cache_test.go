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
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
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

func (t *testDetector) Keywords() []string                 { return nil }
func (t *testDetector) Type() detector_typepb.DetectorType { return -1 }
func (t *testDetector) Description() string                { return "" }

var _ detectors.Detector = (*testDetector)(nil)

// testResultVerifier is a testDetector that can also verify results one at a time, so
// tests can exercise the verification cache's per-result path. It inherits
// fromDataCallCount, which is what proves that path never re-runs the detector to verify.
type testResultVerifier struct {
	testDetector
	verifyResultCallCount int
	// verifyResultCalls records the Redacted value of each verified result in call order,
	// so tests can assert exactly which results were verified rather than just how many.
	verifyResultCalls []string
}

func (t *testResultVerifier) VerifyResult(_ context.Context, result *detectors.Result) {
	t.verifyResultCallCount++
	t.verifyResultCalls = append(t.verifyResultCalls, result.Redacted)

	// Stand in for a remote verification by adopting the status the test declared for this
	// credential. Results are matched on Redacted because that is how these tests identify
	// them; FromData(verify=false) strips verification info, so it has to be restored here.
	for i := range t.results {
		if t.results[i].Redacted == result.Redacted {
			result.CopyVerificationInfo(&t.results[i])
			break
		}
	}

	// As in testDetector.FromData, the metric timing resolution is 1 ms, so verification has
	// to be artificially slow for the wall time it reports to be observable.
	time.Sleep(2 * time.Millisecond)
}

var (
	_ detectors.Detector       = (*testResultVerifier)(nil)
	_ detectors.ResultVerifier = (*testResultVerifier)(nil)
)

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
			assert.Equal(t, detector_typepb.DetectorType(-2), res[0].DetectorType)
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
			assert.Equal(t, detector_typepb.DetectorType(-2), res[0].DetectorType)
		}
	}
	assert.Len(t, cache.resultCache.Values(), 2)
}

// The tests below cover the per-result verification path taken by detectors that implement
// detectors.ResultVerifier.
func TestVerificationCache_FromData_ResultVerifier_PartialCacheHit(t *testing.T) {
	detector := testResultVerifier{testDetector: testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
		{Redacted: "world", Raw: []byte("world"), RawV2: []byte("worldV2"), Verified: false},
	}}}
	detector.results[1].SetVerificationError(errors.New("test verification error"))
	metrics := InMemoryMetrics{}
	cache := New(simple.NewCache[detectors.Result](), &metrics)
	cache.resultCache.Set(getResultCacheKey(t, cache, detector.results[0]),
		detectors.Result{Redacted: "hello", Verified: true})

	results, err := cache.FromData(
		logContext.Background(),
		&detector,
		true,
		false,
		nil)

	require.NoError(t, err)
	// One extraction pass and no re-run: the whole point of the per-result path.
	assert.Equal(t, 1, detector.fromDataCallCount)
	assert.Equal(t, 1, detector.verifyResultCallCount)
	assert.Equal(t, []string{"world"}, detector.verifyResultCalls)
	wantResults := []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true,
			VerificationFromCache: true},
		{Redacted: "world", Raw: []byte("world"), RawV2: []byte("worldV2"), Verified: false},
	}
	wantResults[1].SetVerificationError(errors.New("test verification error"))
	assert.ElementsMatch(t, wantResults, results)
	wantCacheData := []detectors.Result{
		{Redacted: "hello", Verified: true},
		{Redacted: "world", Verified: false},
	}
	wantCacheData[1].SetVerificationError(errors.New("test verification error"))
	assert.ElementsMatch(t, wantCacheData, cache.resultCache.Values())
	assert.Less(t, int64(0), metrics.FromDataVerifyTimeSpentMS.Load())
	assert.Equal(t, int32(1), metrics.CredentialVerificationsSaved.Load())
	assert.Equal(t, int32(1), metrics.ResultCacheHits.Load())
	assert.Equal(t, int32(1), metrics.ResultCacheMisses.Load())
	// Nothing is ever discarded on this path, so no hit can be wasted.
	assert.Equal(t, int32(0), metrics.ResultCacheHitsWasted.Load())
}

func TestVerificationCache_FromData_ResultVerifier_AllCacheHits(t *testing.T) {
	detector := testResultVerifier{testDetector: testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
		{Redacted: "world", Raw: []byte("world"), RawV2: []byte("worldV2"), Verified: false},
	}}}
	metrics := InMemoryMetrics{}
	cache := New(simple.NewCache[detectors.Result](), &metrics)
	cacheData := []detectors.Result{
		{Redacted: "hello", Verified: true},
		{Redacted: "world", Verified: false},
	}
	cacheData[1].SetVerificationError(errors.New("test verification error"))
	cache.resultCache.Set(getResultCacheKey(t, cache, detector.results[0]), cacheData[0])
	cache.resultCache.Set(getResultCacheKey(t, cache, detector.results[1]), cacheData[1])

	results, err := cache.FromData(
		logContext.Background(),
		&detector,
		true,
		false,
		nil)

	require.NoError(t, err)
	assert.Equal(t, 1, detector.fromDataCallCount)
	assert.Equal(t, 0, detector.verifyResultCallCount)
	wantResults := []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true,
			VerificationFromCache: true},
		{Redacted: "world", Raw: []byte("world"), RawV2: []byte("worldV2"), Verified: false,
			VerificationFromCache: true},
	}
	wantResults[1].SetVerificationError(errors.New("test verification error"))
	assert.ElementsMatch(t, wantResults, results)
	assert.ElementsMatch(t, cacheData, cache.resultCache.Values())
	assert.Equal(t, int32(2), metrics.CredentialVerificationsSaved.Load())
	assert.Equal(t, int32(2), metrics.ResultCacheHits.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheMisses.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHitsWasted.Load())
}

func TestVerificationCache_FromData_ResultVerifier_NoCacheHits(t *testing.T) {
	detector := testResultVerifier{testDetector: testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
		{Redacted: "world", Raw: []byte("world"), RawV2: []byte("worldV2"), Verified: false},
	}}}
	detector.results[1].SetVerificationError(errors.New("test verification error"))
	metrics := InMemoryMetrics{}
	cache := New(simple.NewCache[detectors.Result](), &metrics)

	results, err := cache.FromData(
		logContext.Background(),
		&detector,
		true,
		false,
		nil)

	require.NoError(t, err)
	assert.Equal(t, 1, detector.fromDataCallCount)
	assert.Equal(t, 2, detector.verifyResultCallCount)
	assert.Equal(t, []string{"hello", "world"}, detector.verifyResultCalls)
	assert.ElementsMatch(t, detector.results, results)
	// Raw and RawV2 must be absent from every cached entry: this cache outlives the scan of
	// any single chunk, so raw credential material must not be retained in it.
	cachedValues := cache.resultCache.Values()
	assert.Len(t, cachedValues, 2)
	for _, cached := range cachedValues {
		assert.Nil(t, cached.Raw)
		assert.Nil(t, cached.RawV2)
	}
	assert.Less(t, int64(0), metrics.FromDataVerifyTimeSpentMS.Load())
	assert.Equal(t, int32(0), metrics.CredentialVerificationsSaved.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHits.Load())
	assert.Equal(t, int32(2), metrics.ResultCacheMisses.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHitsWasted.Load())
}

// Identical pairs recur within a chunk, so the cache read must happen immediately before
// each verification rather than once up front. Getting this wrong would still be correct,
// just wasteful, which is exactly the class of bug this change exists to remove.
func TestVerificationCache_FromData_ResultVerifier_DuplicateResultsInChunk(t *testing.T) {
	detector := testResultVerifier{testDetector: testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
	}}}
	metrics := InMemoryMetrics{}
	cache := New(simple.NewCache[detectors.Result](), &metrics)

	results, err := cache.FromData(
		logContext.Background(),
		&detector,
		true,
		false,
		nil)

	require.NoError(t, err)
	assert.Equal(t, 1, detector.verifyResultCallCount)
	// The first occurrence is verified remotely and populates the cache; the second reads it
	// back, which is why it reports VerificationFromCache despite the same scan verifying it.
	assert.ElementsMatch(t, []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true,
			VerificationFromCache: true},
	}, results)
	assert.Len(t, cache.resultCache.Values(), 1)
	assert.Equal(t, int32(1), metrics.CredentialVerificationsSaved.Load())
	assert.Equal(t, int32(1), metrics.ResultCacheHits.Load())
	assert.Equal(t, int32(1), metrics.ResultCacheMisses.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHitsWasted.Load())
}

// Implementing ResultVerifier must not make a detector verify when verification is off, so
// the dispatch has to sit after FromData's verify=false early return.
func TestVerificationCache_FromData_ResultVerifier_VerifyFalse(t *testing.T) {
	detector := testResultVerifier{testDetector: testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
	}}}
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
	assert.Equal(t, 0, detector.verifyResultCallCount)
	assert.ElementsMatch(t, []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: false},
	}, results)
	assert.Empty(t, cache.resultCache.Values())
	assert.Equal(t, int64(0), metrics.FromDataVerifyTimeSpentMS.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHits.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheMisses.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHitsWasted.Load())
}

// Targeted re-verification scans (chunk.SecretID != 0) deliberately bypass the cache to get
// a fresh answer, so they must keep going through FromData(verify=true) even for a detector
// that could verify per result.
func TestVerificationCache_FromData_ResultVerifier_ForceCacheUpdate(t *testing.T) {
	detector := testResultVerifier{testDetector: testDetector{results: []detectors.Result{
		{Redacted: "hello", Raw: []byte("hello"), RawV2: []byte("helloV2"), Verified: true},
	}}}
	metrics := InMemoryMetrics{}
	cache := New(simple.NewCache[detectors.Result](), &metrics)
	cache.resultCache.Set(getResultCacheKey(t, cache, detector.results[0]),
		detectors.Result{Redacted: "hello", Verified: false})

	results, err := cache.FromData(
		logContext.Background(),
		&detector,
		true,
		true,
		nil)

	require.NoError(t, err)
	assert.Equal(t, 1, detector.fromDataCallCount)
	assert.Equal(t, 0, detector.verifyResultCallCount)
	assert.ElementsMatch(t, detector.results, results)
	// The stale cached entry is replaced by the freshly verified status.
	assert.ElementsMatch(t, []detectors.Result{{Redacted: "hello", Verified: true}},
		cache.resultCache.Values())
	assert.Less(t, int64(0), metrics.FromDataVerifyTimeSpentMS.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHits.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheMisses.Load())
	assert.Equal(t, int32(0), metrics.ResultCacheHitsWasted.Load())
}
