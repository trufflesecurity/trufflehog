package detectioncaching

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// FromDataCached executes detection on chunk data in a way that uses a provided verification cache to deduplicate
// verification requests when possible.
//
// If the provided cache is nil, all caching logic is skipped, and this function returns the result of the provided
// detector's FromData method.
//
// Otherwise, if forceCacheMiss is true, the provided detector's FromData method is called, and the results are used to
// update the cache before being returned.
//
// Otherwise, if verify is false, all caching logic is skipped, and this function returns the result of the provided
// detector's FromData method.
//
// Otherwise, detection proceeds in two stages. First, detection is executed without verification. Then, the cache is
// queried for each returned result. If all results are cache hits, then their cached values are returned. Otherwise,
// detection is executed again with verification, and the results are used to update the cache before being returned.
func FromDataCached(
	ctx context.Context,
	verificationCache cache.Cache[*detectors.Result],
	getCacheKey func(result *detectors.Result) string,
	detector detectors.Detector,
	verify bool,
	forceCacheMiss bool,
	data []byte,
) ([]detectors.Result, error) {

	if verificationCache == nil {
		return detector.FromData(ctx, verify, data)
	}

	if !forceCacheMiss {
		withoutVerification, err := detector.FromData(ctx, false, data)
		if err != nil {
			return nil, err
		}

		if !verify {
			return withoutVerification, nil
		}

		isEverythingCached := false
		var fromCache []detectors.Result
		for _, r := range withoutVerification {
			if cacheHit, ok := verificationCache.Get(getCacheKey(&r)); ok {
				fromCache = append(fromCache, *cacheHit)
				fromCache[len(fromCache)-1].Raw = r.Raw
				fromCache[len(fromCache)-1].RawV2 = r.RawV2
			} else {
				isEverythingCached = false
				break
			}
		}

		if isEverythingCached {
			return fromCache, nil
		}
	}

	withVerification, err := detector.FromData(ctx, verify, data)
	if err != nil {
		return nil, err
	}

	for _, r := range withVerification {
		copyForCaching := r
		// Do not persist raw secret values in a long-lived cache
		copyForCaching.Raw = nil
		copyForCaching.RawV2 = nil
		// Decoder type will be set later, so clear it out now to minimize the chance of accidentally cloning it
		copyForCaching.DecoderType = detectorspb.DecoderType_UNKNOWN
		verificationCache.Set(getCacheKey(&r), &copyForCaching)
	}

	return withVerification, nil
}
