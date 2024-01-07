package memory

import (
	"strings"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
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
	instance := &Cache{expiration: defaultExpirationInterval, purgeInterval: defaultPurgeInterval}
	for _, opt := range opts {
		opt(instance)
	}

	instance.c = cache.New(instance.expiration, instance.purgeInterval)
	return instance
}

// NewWithData constructs a new in-memory cache with existing data.
// It also accepts CacheOption parameters to override default configuration values.
func NewWithData(ctx context.Context, data []string, opts ...CacheOption) *Cache {
	ctx.Logger().V(3).Info("Loading cache", "num-items", len(data))

	instance := &Cache{expiration: defaultExpirationInterval, purgeInterval: defaultPurgeInterval}
	for _, opt := range opts {
		opt(instance)
	}

	// Convert data slice to map required by go-cache.
	items := make(map[string]cache.Item, len(data))
	for _, d := range data {
		items[d] = cache.Item{Object: d, Expiration: int64(defaultExpiration)}
	}

	instance.c = cache.NewFrom(instance.expiration, instance.purgeInterval, items)
	return instance
}

// Set adds a key-value pair to the cache.
func (c *Cache) Set(key, value string) {
	c.c.Set(key, value, defaultExpiration)
}

// Get returns the value for the given key.
func (c *Cache) Get(key string) (string, bool) {
	res, ok := c.c.Get(key)
	if !ok {
		return "", ok
	}
	return res.(string), ok
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
func (c *Cache) Values() []string {
	items := c.c.Items()
	res := make([]string, 0, len(items))
	for _, v := range items {
		res = append(res, v.Object.(string))
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
