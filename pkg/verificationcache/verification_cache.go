package verificationcache

import (
	"bytes"
	"encoding/binary"
	"sync"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/hasher"
)

// VerificationCache is a structure that can be used to cache verification results from detectors so that a given
// credential does not trigger multiple identical remote verification attempts.
type VerificationCache struct {
	metrics     MetricsReporter
	resultCache ResultCache

	hashMu sync.Mutex
	hasher hasher.Hasher
}

// New creates a new verification cache with the provided result cache and metrics reporter. If resultCache is nil, the
// verification cache will be a no-op passthrough, although it will still record relevant metrics to the provided
// metrics reporter in this case.
func New(resultCache ResultCache, metrics MetricsReporter) *VerificationCache {
	if metrics == nil {
		metrics = &InMemoryMetrics{}
	}

	return &VerificationCache{
		metrics:     metrics,
		resultCache: resultCache,
		hasher:      hasher.NewBlake2B(),
	}
}

// FromData is a cache-aware facade in front of the provided detector's FromData method.
//
// If the verification cache's underlying result cache is nil, or verify is false, or forceCacheUpdate is true, this
// method invokes the provided detector's FromData method with the provided arguments and returns the result. If the
// result cache is non-nil and forceCacheUpdate is true, the result cache is updated with the results before they are
// returned.
//
// Otherwise, the detector's FromData method is called with verify=false. The result cache is then checked for each
// returned result. If there is a cache hit for each result, these cached values are all returned. Otherwise, the
// detector's FromData method is called again, but with verify=true, and the results are stored in the cache and then
// returned.
//
// Detectors that implement detectors.ResultVerifier are handled by verifyCacheMisses instead, which verifies only the
// results that missed the cache rather than re-running the detector over the whole chunk.
func (v *VerificationCache) FromData(
	ctx context.Context,
	detector detectors.Detector,
	verify bool,
	forceCacheUpdate bool,
	data []byte,
) ([]detectors.Result, error) {

	if v.resultCache == nil {
		if verify {
			start := time.Now()
			defer func() {
				v.metrics.AddFromDataVerifyTimeSpent(time.Since(start))
			}()
		}

		return detector.FromData(ctx, verify, data)
	}

	if !forceCacheUpdate {
		withoutRemoteVerification, err := detector.FromData(ctx, false, data)
		if err != nil {
			return nil, err
		}

		if !verify {
			return withoutRemoteVerification, nil
		}

		// avoiding re-running verification for every result in the chunk.
		// only if a detector implements detectors.ResultVerifier
		if resultVerifier, ok := detector.(detectors.ResultVerifier); ok {
			return v.verifyCacheMisses(ctx, resultVerifier, withoutRemoteVerification)
		}
		isEverythingCached := true
		var cacheHitsInCurrentChunk int
		for i, r := range withoutRemoteVerification {
			cacheKey, err := v.getResultCacheKey(r)
			if err != nil {
				ctx.Logger().Error(err, "error getting result cache key for verification caching",
					"operation", "read")
				isEverythingCached = false
				v.metrics.AddResultCacheHitsWasted(cacheHitsInCurrentChunk)
				break
			}
			if cacheHit, ok := v.resultCache.Get(string(cacheKey)); ok {
				withoutRemoteVerification[i].CopyVerificationInfo(&cacheHit)
				withoutRemoteVerification[i].VerificationFromCache = true
				v.metrics.AddResultCacheHits(1)
				cacheHitsInCurrentChunk++
			} else {
				v.metrics.AddResultCacheMisses(1)
				isEverythingCached = false
				v.metrics.AddResultCacheHitsWasted(cacheHitsInCurrentChunk)
				break
			}
		}

		if isEverythingCached {
			v.metrics.AddCredentialVerificationsSaved(len(withoutRemoteVerification))
			return withoutRemoteVerification, nil
		}
	}

	start := time.Now()
	withRemoteVerification, err := detector.FromData(ctx, verify, data)
	if verify {
		v.metrics.AddFromDataVerifyTimeSpent(time.Since(start))
	}
	if err != nil {
		return nil, err
	}

	for _, r := range withRemoteVerification {
		cacheKey, err := v.getResultCacheKey(r)
		if err != nil {
			ctx.Logger().Error(err, "error getting result cache key for verification caching",
				"operation", "write")
			continue
		}

		copyForCaching := r
		// Do not persist raw secret values in a long-lived cache
		copyForCaching.Raw = nil
		copyForCaching.RawV2 = nil
		v.resultCache.Set(string(cacheKey), copyForCaching)
	}

	return withRemoteVerification, nil
}

// verifyCacheMisses serves the results whose verification status is already cached and
// remotely verifies only the misses.
func (v *VerificationCache) verifyCacheMisses(
	ctx context.Context,
	detector detectors.ResultVerifier,
	results []detectors.Result,
) ([]detectors.Result, error) {
	start := time.Now()
	defer func() { v.metrics.AddFromDataVerifyTimeSpent(time.Since(start)) }()

	for i := range results {
		cacheKey, err := v.getResultCacheKey(results[i])
		if err != nil {
			ctx.Logger().Error(err, "error getting result cache key for verification caching",
				"operation", "read")
			// Fail open: a result we cannot key still deserves verification, matching the
			// all-or-nothing path, where a key error falls through to FromData(verify=true).
			detector.VerifyResult(ctx, &results[i])
			continue
		}
		if cacheHit, ok := v.resultCache.Get(string(cacheKey)); ok {
			results[i].CopyVerificationInfo(&cacheHit)
			results[i].VerificationFromCache = true
			v.metrics.AddResultCacheHits(1)
			v.metrics.AddCredentialVerificationsSaved(1)
			continue
		}
		v.metrics.AddResultCacheMisses(1)
		detector.VerifyResult(ctx, &results[i])
		copyForCaching := results[i]
		// Do not persist raw secret values in a long-lived cache
		copyForCaching.Raw = nil
		copyForCaching.RawV2 = nil
		v.resultCache.Set(string(cacheKey), copyForCaching)
	}

	return results, nil
}

func (v *VerificationCache) getResultCacheKey(result detectors.Result) ([]byte, error) {
	v.hashMu.Lock()
	defer v.hashMu.Unlock()

	keyBytes := bytes.Join([][]byte{result.Raw, result.RawV2}, nil)
	keyBytes, err := binary.Append(keyBytes, binary.BigEndian, result.DetectorType)
	if err != nil {
		return nil, err
	}

	return v.hasher.Hash(keyBytes)
}
