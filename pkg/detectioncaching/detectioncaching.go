package detectioncaching

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func FromDataCached(
	ctx context.Context,
	verificationCache cache.Cache[*detectors.Result],
	getCacheKey func(result *detectors.Result) string,
	detector detectors.Detector,
	verify bool,
	forceCacheMiss bool,
	data []byte,
) ([]detectors.Result, error) {

	withoutVerification, err := detector.FromData(ctx, false, data)
	if err != nil {
		return nil, err
	}

	if !verify {
		return withoutVerification, nil
	}

	if !forceCacheMiss {
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

	withVerification, err := detector.FromData(ctx, true, data)
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
