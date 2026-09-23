package verificationcache

import (
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// MetricsReporter is an interface used by a verification cache to report various metrics related to its operation.
// Implementations must be thread-safe.
type MetricsReporter interface {
	// AddCredentialVerificationsSaved records "saved" verification attempts, which is when credential verification
	// status is loaded from the cache instead of retrieved from a remote verification endpoint. This number might be
	// smaller than the cache hit count due to cache hit "wasting"; see AddResultCacheHitsWasted for more information.
	AddCredentialVerificationsSaved(count int)

	// AddFromDataVerifyTimeSpent records wall time spent verifying credentials remotely, either in a call to
	// detector.FromData with verify=true or, for detectors that implement detectors.ResultVerifier, in the
	// per-result verification of cache misses.
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

// DetectorMetricsReporter is an optional interface that a MetricsReporter can additionally implement to receive
// verification timing attributed to the detector that incurred it. Implementations must be thread-safe.
//
// What one sample covers depends on the path taken. When the result cache is consulted, a detectors.ResultVerifier
// records one sample per remote VerifyResult call on a cache miss. Every other case records one sample per whole
// FromData(verify=true) pass, including its regex pass: detectors that do not implement detectors.ResultVerifier,
// targeted rescans (forceCacheUpdate), and a VerificationCache with no result cache. The last two apply to
// ResultVerifier detectors too, so one such detector can produce whole-pass samples that cover many remote calls
// alongside its per-call samples. A detector that starts implementing detectors.ResultVerifier shifts its
// distribution, which resets its baseline rather than signaling a provider change.
type DetectorMetricsReporter interface {
	// AddDetectorVerifyTimeSpent records wall time spent verifying credentials remotely for one detector. It is not
	// called for results served from the cache.
	AddDetectorVerifyTimeSpent(detectorType detector_typepb.DetectorType, wallTime time.Duration)
}
