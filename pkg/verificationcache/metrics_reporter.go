package verificationcache

import "time"

// MetricsReporter is an interface used by a verification cache to report various metrics related to its operation.
type MetricsReporter interface {
	// AddCredentialVerificationsSaved records "saved" verification attempts, which is when credential verification
	// status is loaded from the cache instead of retrieved from a remote verification endpoint. This number might not
	// match the number of cache hits due to hit "wasting"; see AddResultCacheHitsWasted for more information.
	AddCredentialVerificationsSaved(count int)

	// AddFromDataVerifyTimeSpent records wall time spent in calls to FromData with verify = true.
	AddFromDataVerifyTimeSpent(wallTime time.Duration)

	// AddResultCacheHits records result cache hits. Not all cache hits result in elided remote verification requests
	// due to cache hit "wasting"; see AddResultCacheHitsWasted for more information.
	AddResultCacheHits(count int)

	// AddResultCacheMisses records result cache misses.
	AddResultCacheMisses(count int)

	// AddResultCacheHitsWasted records "wasted" result cache hits. A "wasted" result cache hit is a result cache hit
	// that does not elide a remote verification request because there are other secret findings in the relevant chunk
	// that are not cached. When this happens, the detector's FromData method must be called anyway, so the cache hit
	// doesn't save any remote requests.
	AddResultCacheHitsWasted(count int)
}
