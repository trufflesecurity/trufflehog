package detectioncaching

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

func FromDataCached(
	ctx context.Context,
	cache cache.Cache[*detectors.Result],
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

	if forceCacheMiss {
		return verifyAndCache(ctx, cache, detector, data)
	}

	everythingCached := false
	var cachedResults []detectors.Result
	for _, r := range withoutVerification {
		if cacheHit, ok := cache.Get(cacheKey(r)); ok {
			cachedResults = append(cachedResults, *cacheHit)
		} else {
			everythingCached = false
			break
		}
	}

	if everythingCached {
		return cachedResults, nil
	}

	return verifyAndCache(ctx, cache, detector, data)
}

func verifyAndCache(
	ctx context.Context,
	cache cache.Cache[*detectors.Result],
	detector detectors.Detector,
	data []byte,
) ([]detectors.Result, error) {

	results, err := detector.FromData(ctx, true, data)
	if err != nil {
		return nil, err
	}

	for _, r := range results {
		cache.Set(cacheKey(r), &r)
	}

	return results, nil
}

func cacheKey(result detectors.Result) string {
	return string(result.Raw) + string(result.RawV2)
}
