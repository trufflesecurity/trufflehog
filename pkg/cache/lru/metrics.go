package lru

// MetricsCollector should implement the collector interface.
// var _ collector = (*MetricsCollector)(nil)
//
// // MetricsCollector extends the BaseMetricsCollector with Sized LRU specific metrics.
// // It provides methods to record cache evictions.
// type MetricsCollector struct {
// 	// BaseMetricsCollector is embedded to provide the base metrics functionality.
// 	cache.BaseMetricsCollector
//
// 	totalEvicts *prometheus.CounterVec
// }
//
// // NewSizedLRUMetricsCollector initializes a new MetricsCollector with the provided namespace and subsystem.
// func NewSizedLRUMetricsCollector(namespace, subsystem string) *MetricsCollector {
// 	base := cache.GetBaseMetricsCollector()
//
// 	totalEvicts := prometheus.NewCounterVec(prometheus.CounterOpts{
// 		Namespace: namespace,
// 		Subsystem: subsystem,
// 		Name:      "evictions_total",
// 		Help:      "Total number of cache evictions.",
// 	}, []string{"cache_name"})
//
// 	return &MetricsCollector{
// 		BaseMetricsCollector: base,
// 		totalEvicts:          totalEvicts,
// 	}
// }
//
// // RecordEviction increments the total number of cache evictions for the specified cache.
// func (c *MetricsCollector) RecordEviction(cacheName string) {
// 	c.totalEvicts.WithLabelValues(cacheName).Inc()
// }
