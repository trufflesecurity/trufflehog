package verificationcaching

import (
	"context"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

type VerificationCache struct {
	getResultCacheKey func(result detectors.Result) string
	metrics           MetricsReporter
	resultCache       cache.Cache[detectors.Result]
}

func New(
	resultCache cache.Cache[detectors.Result],
	getResultCacheKey func(result detectors.Result) string,
	metrics MetricsReporter,
) VerificationCache {
	return VerificationCache{
		getResultCacheKey: getResultCacheKey,
		metrics:           metrics,
		resultCache:       resultCache,
	}
}

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
				v.metrics.AddFromDataVerifyTimeSpent(time.Since(start).Milliseconds())
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
			if cacheHit, ok := v.resultCache.Get(v.getResultCacheKey(r)); ok {
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
		v.metrics.AddFromDataVerifyTimeSpent(time.Since(start).Milliseconds())
	}
	if err != nil {
		return nil, err
	}

	for _, r := range withRemoteVerification {
		copyForCaching := r
		// Do not persist raw secret values in a long-lived cache
		copyForCaching.Raw = nil
		copyForCaching.RawV2 = nil
		v.resultCache.Set(v.getResultCacheKey(r), copyForCaching)
	}

	return withRemoteVerification, nil
}
