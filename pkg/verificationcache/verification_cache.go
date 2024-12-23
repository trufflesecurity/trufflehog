package verificationcache

import (
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

func (v *VerificationCache) getResultCacheKey(result detectors.Result) ([]byte, error) {
	v.hashMu.Lock()
	defer v.hashMu.Unlock()

	return v.hasher.Hash(append(result.Raw, result.RawV2...))
}
