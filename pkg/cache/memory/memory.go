package memory

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
type Cache struct {
	c             *cache.Cache
	expiration    time.Duration
	purgeInterval time.Duration
}

// CacheOption defines a function type used for configuring a Cache.
type CacheOption func(*Cache)

// WithExpirationInterval returns a CacheOption to set the expiration interval of cache items.
// The interval determines the duration a cached item remains in the cache before it is expired.
func WithExpirationInterval(interval time.Duration) CacheOption {
	return func(c *Cache) { c.expiration = interval }
}

// WithPurgeInterval returns a CacheOption to set the interval at which the cache purges expired items.
// Regular purging helps in freeing up memory by removing stale entries.
func WithPurgeInterval(interval time.Duration) CacheOption {
	return func(c *Cache) { c.purgeInterval = interval }
}

// New constructs a new in-memory cache instance with optional configurations.
// By default, it sets the expiration and purge intervals to 12 and 13 hours, respectively.
// These defaults can be overridden using the functional options: WithExpirationInterval and WithPurgeInterval.
func New(opts ...CacheOption) *Cache {
	return NewWithData(nil, opts...)
}

// CacheEntry represents a single entry in the cache, consisting of a key and its corresponding value.
type CacheEntry struct {
	// Key is the unique identifier for the entry.
	Key string
	// Value is the data stored in the entry.
	Value any
}

// NewWithData constructs a new in-memory cache with existing data.
// It also accepts CacheOption parameters to override default configuration values.
func NewWithData(data []CacheEntry, opts ...CacheOption) *Cache {
	instance := &Cache{expiration: defaultExpirationInterval, purgeInterval: defaultPurgeInterval}
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
func (c *Cache) Set(key string, value any) {
	c.c.Set(key, value, defaultExpiration)
}

// Get returns the value for the given key.
func (c *Cache) Get(key string) (any, bool) {
	return c.c.Get(key)
}

// Exists returns true if the given key exists in the cache.
func (c *Cache) Exists(key string) bool {
	_, ok := c.c.Get(key)
	return ok
}

// Delete removes the key-value pair from the cache.
func (c *Cache) Delete(key string) {
	c.c.Delete(key)
}

// Clear removes all key-value pairs from the cache.
func (c *Cache) Clear() {
	c.c.Flush()
}

// Count returns the number of key-value pairs in the cache.
func (c *Cache) Count() int {
	return c.c.ItemCount()
}

// Keys returns all keys in the cache.
func (c *Cache) Keys() []string {
	items := c.c.Items()
	res := make([]string, 0, len(items))
	for k := range items {
		res = append(res, k)
	}
	return res
}

// Values returns all values in the cache.
func (c *Cache) Values() []any {
	items := c.c.Items()
	res := make([]any, 0, len(items))
	for _, v := range items {
		res = append(res, v.Object)
	}
	return res
}

// Contents returns a comma-separated string containing all keys in the cache.
func (c *Cache) Contents() string {
	items := c.c.Items()
	res := make([]string, 0, len(items))
	for k := range items {
		res = append(res, k)
	}
	return strings.Join(res, ",")
}
