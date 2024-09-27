package cache

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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

// MetricsCollector encapsulates all Prometheus metrics with labels.
// It holds Prometheus counters for cache operations, which help track
// the performance and usage of the cache.
type MetricsCollector struct {
	// Base metrics.
	hits    *prometheus.CounterVec
	misses  *prometheus.CounterVec
	sets    *prometheus.CounterVec
	deletes *prometheus.CounterVec
	clears  *prometheus.CounterVec
}

var (
	collectorOnce sync.Once // Ensures that the collector is initialized only once.
	collector     *MetricsCollector
)

// InitializeMetrics initializes the singleton MetricsCollector.
// It sets up Prometheus counters for cache operations (hits, misses, sets, deletes, clears).
// Should be called once at the start of the application.
func InitializeMetrics(namespace, subsystem string) {
	collectorOnce.Do(func() {
		collector = &MetricsCollector{
			hits: promauto.NewCounterVec(prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "hits_total",
				Help:      "Total number of cache hits.",
			}, []string{"cache_name"}),

			misses: promauto.NewCounterVec(prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "misses_total",
				Help:      "Total number of cache misses.",
			}, []string{"cache_name"}),

			sets: promauto.NewCounterVec(prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "sets_total",
				Help:      "Total number of cache set operations.",
			}, []string{"cache_name"}),

			deletes: promauto.NewCounterVec(prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "deletes_total",
				Help:      "Total number of cache delete operations.",
			}, []string{"cache_name"}),

			clears: promauto.NewCounterVec(prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "clears_total",
				Help:      "Total number of cache clear operations.",
			}, []string{"cache_name"}),
		}
	})
}

// GetMetricsCollector returns the singleton MetricsCollector instance.
// It panics if InitializeMetrics has not been called to ensure metrics are properly initialized.
// Must be called after InitializeMetrics to avoid runtime issues.
// If you do it before, BAD THINGS WILL HAPPEN.
func GetMetricsCollector() *MetricsCollector {
	if collector == nil {
		panic("MetricsCollector not initialized. Call InitializeMetrics first.")
	}
	return collector
}

// Implement BaseMetricsCollector interface methods.

// RecordHit increments the counter for cache hits, tracking how often cache lookups succeed.
func (m *MetricsCollector) RecordHit(cacheName string) { m.hits.WithLabelValues(cacheName).Inc() }

// RecordMiss increments the counter for cache misses, tracking how often cache lookups fail.
func (m *MetricsCollector) RecordMiss(cacheName string) { m.misses.WithLabelValues(cacheName).Inc() }

// RecordSet increments the counter for cache set operations, tracking how often items are added/updated.
func (m *MetricsCollector) RecordSet(cacheName string) { m.sets.WithLabelValues(cacheName).Inc() }

// RecordDelete increments the counter for cache delete operations, tracking how often items are removed.
func (m *MetricsCollector) RecordDelete(cacheName string) { m.deletes.WithLabelValues(cacheName).Inc() }

// RecordClear increments the counter for cache clear operations, tracking how often the cache is completely cleared.
func (m *MetricsCollector) RecordClear(cacheName string) { m.clears.WithLabelValues(cacheName).Inc() }
