package cache

import (
	"sync"

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

// BaseCollector encapsulates all Prometheus metrics with labels.
// It holds Prometheus counters for cache operations, which help track
// the performance and usage of the cache.
type BaseCollector struct {
	// Base metrics.
	hits    *prometheus.CounterVec
	misses  *prometheus.CounterVec
	sets    *prometheus.CounterVec
	deletes *prometheus.CounterVec
	clears  *prometheus.CounterVec
}

func init() {
	// Initialize the singleton BaseCollector.
	// Set up Prometheus counters for cache operations (hits, misses, sets, deletes, clears).
	baseCollectorOnce.Do(func() {
		baseCollector = &BaseCollector{
			hits: promauto.NewCounterVec(prometheus.CounterOpts{
				Namespace: common.MetricsNamespace,
				Subsystem: common.MetricsSubsystem,
				Name:      "hits_total",
				Help:      "Total number of cache hits.",
			}, []string{"cache_name"}),

			misses: promauto.NewCounterVec(prometheus.CounterOpts{
				Namespace: common.MetricsNamespace,
				Subsystem: common.MetricsSubsystem,
				Name:      "misses_total",
				Help:      "Total number of cache misses.",
			}, []string{"cache_name"}),

			sets: promauto.NewCounterVec(prometheus.CounterOpts{
				Namespace: common.MetricsNamespace,
				Subsystem: common.MetricsSubsystem,
				Name:      "sets_total",
				Help:      "Total number of cache set operations.",
			}, []string{"cache_name"}),

			deletes: promauto.NewCounterVec(prometheus.CounterOpts{
				Namespace: common.MetricsNamespace,
				Subsystem: common.MetricsSubsystem,
				Name:      "deletes_total",
				Help:      "Total number of cache delete operations.",
			}, []string{"cache_name"}),

			clears: promauto.NewCounterVec(prometheus.CounterOpts{
				Namespace: common.MetricsNamespace,
				Subsystem: common.MetricsSubsystem,
				Name:      "clears_total",
				Help:      "Total number of cache clear operations.",
			}, []string{"cache_name"}),
		}
	})

	// Initialize the singleton EvictionMetrics.
	// Set up Prometheus counters for cache evictions.
	evictionCollectorOnce.Do(func() {
		evictionCollector = &EvictionMetrics{
			evictions: promauto.NewCounterVec(prometheus.CounterOpts{
				Namespace: common.MetricsNamespace,
				Subsystem: common.MetricsSubsystem,
				Name:      "evictions_total",
				Help:      "Total number of cache evictions.",
			}, []string{"cache_name"}),
		}
	})
}

var (
	baseCollectorOnce sync.Once // Ensures that the baseCollector is initialized only once.
	baseCollector     *BaseCollector

	evictionCollectorOnce sync.Once
	evictionCollector     *EvictionMetrics
)

// GetBaseMetricsCollector returns the singleton BaseCollector instance.
func GetBaseMetricsCollector() *BaseCollector {
	if baseCollector == nil {
		panic("BaseCollector not initialized. Call InitializeMetrics first.")
	}
	return baseCollector
}

// GetEvictionMetricsCollector returns the singleton EvictionMetrics instance.
func GetEvictionMetricsCollector() *EvictionMetrics {
	if evictionCollector == nil {
		panic("EvictionMetrics not initialized. Call InitializeMetrics first.")
	}
	return evictionCollector
}

// Implement BaseMetricsCollector interface methods.

// RecordHit increments the counter for cache hits, tracking how often cache lookups succeed.
func (m *BaseCollector) RecordHit(cacheName string) { m.hits.WithLabelValues(cacheName).Inc() }

// RecordMiss increments the counter for cache misses, tracking how often cache lookups fail.
func (m *BaseCollector) RecordMiss(cacheName string) { m.misses.WithLabelValues(cacheName).Inc() }

// RecordSet increments the counter for cache set operations, tracking how often items are added/updated.
func (m *BaseCollector) RecordSet(cacheName string) { m.sets.WithLabelValues(cacheName).Inc() }

// RecordDelete increments the counter for cache delete operations, tracking how often items are removed.
func (m *BaseCollector) RecordDelete(cacheName string) { m.deletes.WithLabelValues(cacheName).Inc() }

// RecordClear increments the counter for cache clear operations, tracking how often the cache is completely cleared.
func (m *BaseCollector) RecordClear(cacheName string) { m.clears.WithLabelValues(cacheName).Inc() }

// EvictionMetrics implements EvictionMetricsCollector interface.
type EvictionMetrics struct {
	evictions *prometheus.CounterVec
}

// Implement EvictionMetricsCollector interface method.

func (em *EvictionMetrics) RecordEviction(cacheName string) {
	em.evictions.WithLabelValues(cacheName).Inc()
}
