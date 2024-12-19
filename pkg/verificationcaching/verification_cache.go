package verificationcaching

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

type VerificationCache struct {
	getResultCacheKey func(result detectors.Result) string
	resultCache       cache.Cache[detectors.Result]

	Metrics VerificationCacheMetrics
}

type VerificationCacheMetrics struct {
	CredentialVerificationsSaved atomic.Int32
	FromDataVerifyTimeSpentMS    atomic.Int64
	ResultCacheHits              atomic.Int32
	ResultCacheHitsWasted        atomic.Int32
	ResultCacheMisses            atomic.Int32
}

func New(
	resultCache cache.Cache[detectors.Result],
	getResultCacheKey func(result detectors.Result) string,
) VerificationCache {
	return VerificationCache{
		getResultCacheKey: getResultCacheKey,
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
				v.Metrics.FromDataVerifyTimeSpentMS.Add(time.Since(start).Milliseconds())
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
		var cacheHitsInCurrentChunk int32
		for i, r := range withoutRemoteVerification {
			if cacheHit, ok := v.resultCache.Get(v.getResultCacheKey(r)); ok {
				withoutRemoteVerification[i].CopyVerificationInfo(&cacheHit)
				withoutRemoteVerification[i].VerificationFromCache = true
				v.Metrics.ResultCacheHits.Add(1)
				cacheHitsInCurrentChunk++
			} else {
				v.Metrics.ResultCacheMisses.Add(1)
				isEverythingCached = false
				v.Metrics.ResultCacheHitsWasted.Add(cacheHitsInCurrentChunk)
				break
			}
		}

		if isEverythingCached {
			v.Metrics.CredentialVerificationsSaved.Add(int32(len(withoutRemoteVerification)))
			return withoutRemoteVerification, nil
		}
	}

	start := time.Now()
	withRemoteVerification, err := detector.FromData(ctx, verify, data)
	if verify {
		v.Metrics.FromDataVerifyTimeSpentMS.Add(time.Since(start).Milliseconds())
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
