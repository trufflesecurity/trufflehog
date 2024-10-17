package cache

// WithMetrics is a decorator that adds metrics collection to any Cache implementation.
type WithMetrics[T any] struct {
	wrapped   Cache[T]
	metrics   BaseMetricsCollector
	cacheName string
}

// NewCacheWithMetrics creates a new WithMetrics decorator that wraps the provided Cache
// and collects metrics using the provided BaseMetricsCollector.
// The cacheName parameter is used to identify the cache in the collected metrics.
func NewCacheWithMetrics[T any](wrapped Cache[T], metrics BaseMetricsCollector, cacheName string) *WithMetrics[T] {
	return &WithMetrics[T]{
		wrapped:   wrapped,
		metrics:   metrics,
		cacheName: cacheName,
	}
}

// Set sets the value for the given key in the cache. It also records a set metric
// for the cache using the provided metrics collector and cache name.
func (c *WithMetrics[T]) Set(key string, val T) {
	c.metrics.RecordSet(c.cacheName)
	c.wrapped.Set(key, val)
}

// Get retrieves the value for the given key from the underlying cache. It also records
// a hit or miss metric for the cache using the provided metrics collector and cache name.
func (c *WithMetrics[T]) Get(key string) (T, bool) {
	val, found := c.wrapped.Get(key)
	if found {
		c.metrics.RecordHit(c.cacheName)
	} else {
		c.metrics.RecordMiss(c.cacheName)
	}
	return val, found
}

// Exists checks if the given key exists in the cache. It records a hit or miss metric
// for the cache using the provided metrics collector and cache name.
func (c *WithMetrics[T]) Exists(key string) bool {
	found := c.wrapped.Exists(key)
	if found {
		c.metrics.RecordHit(c.cacheName)
	} else {
		c.metrics.RecordMiss(c.cacheName)
	}
	return found
}

// Delete removes the value for the given key from the cache. It also records a delete metric
// for the cache using the provided metrics collector and cache name.
func (c *WithMetrics[T]) Delete(key string) {
	c.wrapped.Delete(key)
	c.metrics.RecordDelete(c.cacheName)
}

// Clear removes all entries from the cache. It also records a clear metric
// for the cache using the provided metrics collector and cache name.
func (c *WithMetrics[T]) Clear() {
	c.wrapped.Clear()
	c.metrics.RecordClear(c.cacheName)
}

// Count returns the number of entries in the cache. It also records a count metric
// for the cache using the provided metrics collector and cache name.
func (c *WithMetrics[T]) Count() int {
	count := c.wrapped.Count()
	return count
}

// Keys returns all keys in the cache. It also records a keys metric
// for the cache using the provided metrics collector and cache name.
func (c *WithMetrics[T]) Keys() []string { return c.wrapped.Keys() }

// Values returns all values in the cache. It also records a values metric
// for the cache using the provided metrics collector and cache name.
func (c *WithMetrics[T]) Values() []T { return c.wrapped.Values() }

// Contents returns all keys in the cache as a string. It also records a contents metric
// for the cache using the provided metrics collector and cache name.
func (c *WithMetrics[T]) Contents() string { return c.wrapped.Contents() }
