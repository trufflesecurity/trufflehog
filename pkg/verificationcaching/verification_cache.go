package verificationcaching

import (
	"sync"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/hasher"
)

type VerificationCache struct {
	metrics     MetricsReporter
	resultCache ResultCache

	hashMu sync.Mutex
	hasher hasher.Hasher
}

func New(
	resultCache ResultCache,
	metrics MetricsReporter,
) VerificationCache {
	return VerificationCache{
		metrics:     metrics,
		resultCache: resultCache,
		hasher:      hasher.NewBlake2B(),
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
		v.metrics.AddFromDataVerifyTimeSpent(time.Since(start).Milliseconds())
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
