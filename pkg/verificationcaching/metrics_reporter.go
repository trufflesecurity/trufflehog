package verificationcaching

type MetricsReporter interface {
	AddCredentialVerificationsSaved(count int)
	AddFromDataVerifyTimeSpent(ms int64)
	AddResultCacheHits(count int)
	AddResultCacheMisses(count int)
	AddResultCacheHitsWasted(count int)
}
