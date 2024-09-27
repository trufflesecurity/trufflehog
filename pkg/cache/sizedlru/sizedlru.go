// Package sizedlru provides a generic, size-limited, LRU (Least Recently Used) cache with optional
// metrics collection and reporting. It wraps the golang-lru/v2 caching library, adding support for custom
// metrics tracking cache hits, misses, evictions, and other cache operations.
//
// This package supports configuring key aspects of cache behavior, including maximum cache size,
// and custom metrics collection.
package sizedlru

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// collector is an interface that extends cache.BaseMetricsCollector
// and adds methods for recording cache hits, misses, and evictions.
type collector interface {
	cache.BaseMetricsCollector

	RecordEviction(cacheName string)
}

// Cache is a generic LRU-sized cache that stores key-value pairs with a maximum size limit.
// It wraps the lru.Cache library and adds support for custom metrics collection.
type Cache[T any] struct {
	cache *lru.Cache[string, T]

	cacheName string
	capacity  int
	metrics   collector
}

// Option defines a functional option for configuring the Cache.
type Option[T any] func(*Cache[T])

// WithMetricsCollector is a functional option to set a custom metrics collector.
// It sets the metrics field of the Cache.
func WithMetricsCollector[T any](collector collector) Option[T] {
	return func(lc *Cache[T]) { lc.metrics = collector }
}

// WithCapacity is a functional option to set the maximum capacity of the cache.
// If the capacity is not set, the default value (512MB) is used.
func WithCapacity[T any](capacity int) Option[T] {
	return func(lc *Cache[T]) { lc.capacity = capacity }
}

// NewCache creates a new Cache with optional configuration parameters.
// It takes a cache name and a variadic list of options.
func NewCache[T any](cacheName string, opts ...Option[T]) (*Cache[T], error) {
	// Default values for cache configuration.
	const defaultSize = 1 << 29 // 512MB

	sizedLRU := &Cache[T]{
		metrics:   NewSizedLRUMetricsCollector(common.MetricsNamespace, common.MetricsSubsystem),
		cacheName: cacheName,
	}

	for _, opt := range opts {
		opt(sizedLRU)
	}

	// Provide a evict callback function to record evictions.
	onEvicted := func(string, T) {
		sizedLRU.metrics.RecordEviction(sizedLRU.cacheName)
	}

	lcache, err := lru.NewWithEvict[string, T](defaultSize, onEvicted)
	if err != nil {
		return nil, fmt.Errorf("failed to create Ristretto cache: %w", err)
	}

	sizedLRU.cache = lcache

	return sizedLRU, nil
}

// Set adds a key-value pair to the cache.
func (lc *Cache[T]) Set(key string, val T) {
	lc.cache.Add(key, val)
	lc.metrics.RecordSet(lc.cacheName)
}

// Get retrieves a value from the cache by key.
func (lc *Cache[T]) Get(key string) (T, bool) {
	value, found := lc.cache.Get(key)
	if found {
		lc.metrics.RecordHit(lc.cacheName)
		return value, true
	}
	lc.metrics.RecordMiss(lc.cacheName)
	var zero T
	return zero, false
}

// Exists checks if a key exists in the cache.
func (lc *Cache[T]) Exists(key string) bool {
	_, found := lc.cache.Get(key)
	if found {
		lc.metrics.RecordHit(lc.cacheName)
	} else {
		lc.metrics.RecordMiss(lc.cacheName)
	}
	return found
}

// Delete removes a key from the cache.
func (lc *Cache[T]) Delete(key string) {
	lc.cache.Remove(key)
	lc.metrics.RecordDelete(lc.cacheName)
}

// Clear removes all keys from the cache.
func (lc *Cache[T]) Clear() {
	lc.cache.Purge()
	lc.metrics.RecordClear(lc.cacheName)
}
