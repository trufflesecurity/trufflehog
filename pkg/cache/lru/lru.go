// Package lru provides a generic, size-limited, LRU (Least Recently Used) cache with optional
// metrics collection and reporting. It wraps the golang-lru/v2 caching library, adding support for custom
// metrics tracking cache hits, misses, evictions, and other cache operations.
//
// This package supports configuring key aspects of cache behavior, including maximum cache size,
// and custom metrics collection.
package lru

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
)

// Cache is a generic LRU-sized cache that stores key-value pairs with a maximum size limit.
// It wraps the lru.Cache library and adds support for custom metrics collection.
type Cache[T any] struct {
	cache *lru.Cache[string, T]

	cacheName    string
	capacity     int
	evictMetrics cache.EvictionMetricsCollector
}

// Option defines a functional option for configuring the Cache.
type Option[T any] func(*Cache[T])

// WithCapacity is a functional option to set the maximum number of items the cache can hold.
// If the capacity is not set, the default value (128_000) is used.
func WithCapacity[T any](capacity int) Option[T] {
	return func(lc *Cache[T]) { lc.capacity = capacity }
}

// WithMetricsCollector is a functional option to set a custom metrics collector.
func WithMetricsCollector[T any](collector cache.EvictionMetricsCollector) Option[T] {
	return func(lc *Cache[T]) { lc.evictMetrics = collector }
}

// NewCache creates a new Cache with optional configuration parameters.
// It takes a cache name and a variadic list of options.
func NewCache[T any](cacheName string, opts ...Option[T]) (*Cache[T], error) {
	// Default values for cache configuration.
	const defaultSize = 128_000

	sizedLRU := &Cache[T]{
		cacheName: cacheName,
	}

	for _, opt := range opts {
		opt(sizedLRU)
	}

	var onEvicted func(string, T)
	// Provide a evict callback function to record evictions if a custom metrics collector is provided.
	if sizedLRU.evictMetrics != nil {
		onEvicted = func(string, T) {
			sizedLRU.evictMetrics.RecordEviction(sizedLRU.cacheName)
		}
	}

	lcache, err := lru.NewWithEvict[string, T](defaultSize, onEvicted)
	if err != nil {
		return nil, fmt.Errorf("failed to create lrusized cache: %w", err)
	}

	sizedLRU.cache = lcache

	return sizedLRU, nil
}

// Set adds a key-value pair to the cache.
func (lc *Cache[T]) Set(key string, val T) { lc.cache.Add(key, val) }

// Get retrieves a value from the cache by key.
func (lc *Cache[T]) Get(key string) (T, bool) {
	value, found := lc.cache.Get(key)
	if found {
		return value, true
	}
	var zero T
	return zero, false
}

// Exists checks if a key exists in the cache.
func (lc *Cache[T]) Exists(key string) bool {
	_, found := lc.cache.Get(key)
	return found
}

// Delete removes a key from the cache.
func (lc *Cache[T]) Delete(key string) {
	lc.cache.Remove(key)
}

// Clear removes all keys from the cache.
func (lc *Cache[T]) Clear() {
	lc.cache.Purge()
}

// Count returns the number of key-value pairs in the cache.
func (lc *Cache[T]) Count() int { return lc.cache.Len() }

// Keys returns all keys in the cache.
func (lc *Cache[T]) Keys() []string { return lc.cache.Keys() }

// Values returns all values in the cache.
func (lc *Cache[T]) Values() []T {
	items := lc.cache.Keys()
	res := make([]T, 0, len(items))
	for _, k := range items {
		v, _ := lc.cache.Get(k)
		res = append(res, v)
	}
	return res
}

// Contents returns all keys in the cache encoded as a string.
func (lc *Cache[T]) Contents() string {
	return fmt.Sprintf("%v", lc.cache.Keys())
}
