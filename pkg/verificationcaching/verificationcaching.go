package verificationcaching

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

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
	getCacheKey func(result *detectors.Result) string,
	detector detectors.Detector,
	verify bool,
	forceCacheUpdate bool,
	data []byte,
) ([]detectors.Result, error) {

	if verificationCache == nil {
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
		for i, r := range withoutRemoteVerification {
			if cacheHit, ok := verificationCache.Get(getCacheKey(&r)); ok {
				withoutRemoteVerification[i].CopyVerificationInfo(&cacheHit)
				withoutRemoteVerification[i].VerificationFromCache = true
			} else {
				isEverythingCached = false
				break
			}
		}

		if isEverythingCached {
			return withoutRemoteVerification, nil
		}
	}

	withRemoteVerification, err := detector.FromData(ctx, verify, data)
	if err != nil {
		return nil, err
	}

	for _, r := range withRemoteVerification {
		copyForCaching := r
		// Do not persist raw secret values in a long-lived cache
		copyForCaching.Raw = nil
		copyForCaching.RawV2 = nil
		verificationCache.Set(getCacheKey(&r), copyForCaching)
	}

	return withRemoteVerification, nil
}
