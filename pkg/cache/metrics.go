package cache

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// BaseMetricsCollector defines the interface for recording cache metrics.
// Each method corresponds to a specific cache-related operation.
type BaseMetricsCollector interface {
	RecordHit(cacheName string)
	RecordMiss(cacheName string)
	RecordSet(cacheName string)
	RecordDelete(cacheName string)
	RecordClear(cacheName string)
}

// EvictionMetricsCollector defines the interface for recording cache-specific eviction metrics.
type EvictionMetricsCollector interface {
	RecordEviction(cacheName string)
}

// baseCollector encapsulates all Prometheus metrics with labels.
// It holds Prometheus counters for cache operations, which help track
// the performance and usage of the cache.
type baseCollector struct {
	// Base metrics.
	hits    *prometheus.CounterVec
	misses  *prometheus.CounterVec
	sets    *prometheus.CounterVec
	deletes *prometheus.CounterVec
	clears  *prometheus.CounterVec
}

func init() {
	// Initialize the singleton baseCollector.
	// Set up Prometheus counters for cache operations (hits, misses, sets, deletes, clears).
	baseMetricsInstance = &baseCollector{
		hits: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "hits_total",
			Help:      "Total number of cache hits.",
		}, []string{"cache_name"}),

		misses: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "misses_total",
			Help:      "Total number of cache misses.",
		}, []string{"cache_name"}),

		sets: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "sets_total",
			Help:      "Total number of cache set operations.",
		}, []string{"cache_name"}),

		deletes: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "deletes_total",
			Help:      "Total number of cache delete operations.",
		}, []string{"cache_name"}),

		clears: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "clears_total",
			Help:      "Total number of cache clear operations.",
		}, []string{"cache_name"}),
	}

	// Initialize the singleton evictionMetrics.
	// Set up Prometheus counters for cache evictions.
	evictionMetricsInstance = &evictionMetrics{
		evictions: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "evictions_total",
			Help:      "Total number of cache evictions.",
		}, []string{"cache_name"}),
	}
}

var (
	baseMetricsInstance     *baseCollector
	evictionMetricsInstance *evictionMetrics
)

// GetBaseMetricsCollector returns the singleton baseCollector instance.
func GetBaseMetricsCollector() BaseMetricsCollector { return baseMetricsInstance }

// GetEvictionMetricsCollector returns the singleton evictionMetrics instance.
func GetEvictionMetricsCollector() EvictionMetricsCollector { return evictionMetricsInstance }

// Implement BaseMetricsCollector interface methods.

// RecordHit increments the counter for cache hits, tracking how often cache lookups succeed.
func (m *baseCollector) RecordHit(cacheName string) { m.hits.WithLabelValues(cacheName).Inc() }

// RecordMiss increments the counter for cache misses, tracking how often cache lookups fail.
func (m *baseCollector) RecordMiss(cacheName string) { m.misses.WithLabelValues(cacheName).Inc() }

// RecordSet increments the counter for cache set operations, tracking how often items are added/updated.
func (m *baseCollector) RecordSet(cacheName string) { m.sets.WithLabelValues(cacheName).Inc() }

// RecordDelete increments the counter for cache delete operations, tracking how often items are removed.
func (m *baseCollector) RecordDelete(cacheName string) { m.deletes.WithLabelValues(cacheName).Inc() }

// RecordClear increments the counter for cache clear operations, tracking how often the cache is completely cleared.
func (m *baseCollector) RecordClear(cacheName string) { m.clears.WithLabelValues(cacheName).Inc() }

// evictionMetrics implements EvictionMetricsCollector interface.
type evictionMetrics struct {
	evictions *prometheus.CounterVec
}

// Implement EvictionMetricsCollector interface method.

func (em *evictionMetrics) RecordEviction(cacheName string) {
	em.evictions.WithLabelValues(cacheName).Inc()
}
