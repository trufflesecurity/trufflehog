package verificationcache

import (
	"sync/atomic"
	"time"
)

// InMemoryMetrics is a MetricsReporter that stores reported metrics in memory for retrieval at the end of a scan.
type InMemoryMetrics struct {
	CredentialVerificationsSaved atomic.Int32
	FromDataVerifyTimeSpentMS    atomic.Int64
	ResultCacheHits              atomic.Int32
	ResultCacheHitsWasted        atomic.Int32
	ResultCacheMisses            atomic.Int32
}

var _ MetricsReporter = (*InMemoryMetrics)(nil)

func (m *InMemoryMetrics) AddCredentialVerificationsSaved(count int) {
	m.CredentialVerificationsSaved.Add(int32(count))
}

func (m *InMemoryMetrics) AddFromDataVerifyTimeSpent(wallTime time.Duration) {
	m.FromDataVerifyTimeSpentMS.Add(wallTime.Milliseconds())
}

func (m *InMemoryMetrics) AddResultCacheHits(count int) {
	m.ResultCacheHits.Add(int32(count))
}

func (m *InMemoryMetrics) AddResultCacheMisses(count int) {
	m.ResultCacheMisses.Add(int32(count))
}

func (m *InMemoryMetrics) AddResultCacheHitsWasted(count int) {
	m.ResultCacheHitsWasted.Add(int32(count))
}
