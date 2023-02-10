package cache

import (
	"sync"
)

// Cache in-memory cache.
type Cache struct {
	mu sync.RWMutex
	m  map[string]string
}

// Simple constructs a new Simple cache.
func Simple() *Cache {
	return &Cache{
		m: make(map[string]string),
	}
}

// Set a value in the cache.
func (c *Cache) Set(key, value string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = value
	return nil
}

// Get a value and a boolean indicating if the value was found.
func (c *Cache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, ok := c.m[key]
	return value, ok
}

// Delete a value from the cache.
func (c *Cache) Delete(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
	return nil
}

// Clear the cache.
func (c *Cache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = make(map[string]string)
	return nil
}
