package memory

import (
	"strings"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const (
	expirationInterval = 12 * time.Hour
	purgeInterval      = 13 * time.Hour
	defaultExpiration  = cache.DefaultExpiration
)

// Cache is a wrapper around the Ristretto in-memory cache.
type Cache struct {
	c *cache.Cache
}

// New constructs a new in-memory cache.
func New() *Cache {
	c := cache.New(expirationInterval, purgeInterval)
	return &Cache{c: c}
}

// NewWithData constructs a new in-memory cache with existing data.
func NewWithData(ctx context.Context, s string) *Cache {
	data := strings.Split(s, ",")
	ctx.Logger().V(3).Info("Loading cache", "num-items", len(data))

	var items map[string]cache.Item
	for _, d := range data {
		items[d] = cache.Item{Object: d, Expiration: int64(defaultExpiration)}
	}

	c := cache.NewFrom(expirationInterval, purgeInterval, items)
	return &Cache{c: c}
}

// Set adds a key-value pair to the cache.
func (c *Cache) Set(key string, value bool) {
	c.c.Set(key, value, defaultExpiration)
}

// Get returns the value for the given key.
func (c *Cache) Get(key string) (string, bool) {
	_, ok := c.c.Get(key)
	return "", ok
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

// Contents returns all key-value pairs in the cache encodes as a string.
func (c *Cache) Contents() string {
	items := c.c.Items()
	res := make([]string, 0, len(items))
	for k := range items {
		res = append(res, k)
	}
	return strings.Join(res, ",")
}
