package verificationcaching

import (
	"sync/atomic"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

var CacheHits atomic.Int32
var CacheHitsWasted atomic.Int32
var CacheMisses atomic.Int32
var VerificationCallsSaved atomic.Int32
var VerificationTimeSpentMS atomic.Int64

// FromDataCached executes detection on chunk data in a way that uses a provided verification cache to deduplicate
// verification requests when possible.
//
// If the provided cache is nil, this function simply returns the result of the provided detector's FromData method.
//
// If verify is false, this function returns the result of the provided detector's FromData method. In this case, the
// cache is only updated if forceCacheUpdate is true.
//
// If verify is true, and forceCacheUpdate is false, this function first executes the provided detector's FromData
// method with verification disabled. Then, the cache is queried for each result. If they are all present in the cache,
// the cached values are returned. Otherwise, the provided detector's FromData method is invoked (again) with
// verification enabled, and the results are used to update the cache before being returned.
//
// If verify is true, and forceCacheUpdate is also true, the provided detector's FromData method is invoked, and the
// results are used to update the cache before being returned.
func FromDataCached(
	ctx context.Context,
	verificationCache cache.Cache[detectors.Result],
	getCacheKey func(result detectors.Result) string,
	detector detectors.Detector,
	verify bool,
	forceCacheUpdate bool,
	data []byte,
) ([]detectors.Result, error) {

	if verificationCache == nil {
		start := time.Now()
		defer func() {
			if verify {
				VerificationTimeSpentMS.Add(time.Since(start).Milliseconds())
			}
		}()
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
		var cacheHitsInCurrentChunk int32
		for i, r := range withoutRemoteVerification {
			if cacheHit, ok := verificationCache.Get(getCacheKey(r)); ok {
				withoutRemoteVerification[i].CopyVerificationInfo(&cacheHit)
				withoutRemoteVerification[i].VerificationFromCache = true
				CacheHits.Add(1)
				cacheHitsInCurrentChunk++
			} else {
				CacheMisses.Add(1)
				isEverythingCached = false
				CacheHitsWasted.Add(cacheHitsInCurrentChunk)
				break
			}
		}

		if isEverythingCached {
			VerificationCallsSaved.Add(int32(len(withoutRemoteVerification)))
			return withoutRemoteVerification, nil
		}
	}

	start := time.Now()
	withRemoteVerification, err := detector.FromData(ctx, verify, data)
	if verify {
		VerificationTimeSpentMS.Add(time.Since(start).Milliseconds())
	}
	if err != nil {
		return nil, err
	}

	for _, r := range withRemoteVerification {
		copyForCaching := r
		// Do not persist raw secret values in a long-lived cache
		copyForCaching.Raw = nil
		copyForCaching.RawV2 = nil
		verificationCache.Set(getCacheKey(r), copyForCaching)
	}

	return withRemoteVerification, nil
}
