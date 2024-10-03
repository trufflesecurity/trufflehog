package simple

import (
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)

const (
	defaultExpirationInterval = 12 * time.Hour
	defaultPurgeInterval      = 13 * time.Hour
	defaultExpiration         = cache.DefaultExpiration
)

// Cache wraps the go-cache library to provide an in-memory key-value store.
type Cache[T any] struct {
	c             *cache.Cache
	expiration    time.Duration
	purgeInterval time.Duration
}

// CacheOption defines a function type used for configuring a Cache.
type CacheOption[T any] func(*Cache[T])

// WithExpirationInterval returns a CacheOption to set the expiration interval of cache items.
// The interval determines the duration a cached item remains in the cache before it is expired.
func WithExpirationInterval[T any](interval time.Duration) CacheOption[T] {
	return func(c *Cache[T]) { c.expiration = interval }
}

// WithPurgeInterval returns a CacheOption to set the interval at which the cache purges expired items.
// Regular purging helps in freeing up memory by removing stale entries.
func WithPurgeInterval[T any](interval time.Duration) CacheOption[T] {
	return func(c *Cache[T]) { c.purgeInterval = interval }
}

// NewCache constructs a new in-memory cache instance with optional configurations.
// By default, it sets the expiration and purge intervals to 12 and 13 hours, respectively.
// These defaults can be overridden using the functional options: WithExpirationInterval and WithPurgeInterval.
func NewCache[T any](opts ...CacheOption[T]) *Cache[T] {
	return NewCacheWithData[T](nil, opts...)
}

// CacheEntry represents a single entry in the cache, consisting of a key and its corresponding value.
type CacheEntry[T any] struct {
	// Key is the unique identifier for the entry.
	Key string
	// Value is the data stored in the entry.
	Value T
}

// NewCacheWithData constructs a new in-memory cache with existing data.
// It also accepts CacheOption parameters to override default configuration values.
func NewCacheWithData[T any](data []CacheEntry[T], opts ...CacheOption[T]) *Cache[T] {
	instance := &Cache[T]{expiration: defaultExpirationInterval, purgeInterval: defaultPurgeInterval}
	for _, opt := range opts {
		opt(instance)
	}

	// Convert data slice to map required by go-cache.
	items := make(map[string]cache.Item, len(data))
	for _, d := range data {
		items[d.Key] = cache.Item{Object: d.Value, Expiration: int64(defaultExpiration)}
	}

	instance.c = cache.NewFrom(instance.expiration, instance.purgeInterval, items)
	return instance
}

// Set adds a key-value pair to the cache.
func (c *Cache[T]) Set(key string, value T) {
	c.c.Set(key, value, defaultExpiration)
}

// Get returns the value for the given key.
func (c *Cache[T]) Get(key string) (T, bool) {
	var value T

	v, ok := c.c.Get(key)
	if !ok {
		return value, false
	}

	value, ok = v.(T)
	return value, ok
}

// Exists returns true if the given key exists in the cache.
func (c *Cache[T]) Exists(key string) bool {
	_, ok := c.c.Get(key)
	return ok
}

// Delete removes the key-value pair from the cache.
func (c *Cache[T]) Delete(key string) {
	c.c.Delete(key)
}

// Clear removes all key-value pairs from the cache.
func (c *Cache[T]) Clear() {
	c.c.Flush()
}

// Count returns the number of key-value pairs in the cache.
func (c *Cache[T]) Count() int {
	return c.c.ItemCount()
}

// Keys returns all keys in the cache.
func (c *Cache[T]) Keys() []string {
	items := c.c.Items()
	res := make([]string, 0, len(items))
	for k := range items {
		res = append(res, k)
	}
	return res
}

// Values returns all values in the cache.
func (c *Cache[T]) Values() []T {
	items := c.c.Items()
	res := make([]T, 0, len(items))
	for _, v := range items {
		obj, ok := v.Object.(T)
		if ok {
			res = append(res, obj)
		}
	}
	return res
}

// Contents returns a comma-separated string containing all keys in the cache.
func (c *Cache[T]) Contents() string {
	items := c.c.Items()
	res := make([]string, 0, len(items))
	for k := range items {
		res = append(res, k)
	}
	return strings.Join(res, ",")
}
