package verificationcaching

// MetricsReporter is an interface used by a verification cache to report various metrics on its operation.
type MetricsReporter interface {
	AddCredentialVerificationsSaved(count int)
	AddFromDataVerifyTimeSpent(ms int64)
	AddResultCacheHits(count int)
	AddResultCacheMisses(count int)
	AddResultCacheHitsWasted(count int)
}
