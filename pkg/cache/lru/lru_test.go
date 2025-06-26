package lru

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockCollector struct{ mock.Mock }

func (m *mockCollector) RecordEviction(cacheName string) { m.Called(cacheName) }

// setupCache initializes the metrics and cache.
// If withCollector is true, it sets up a cache with a custom metrics collector.
// Otherwise, it sets up a cache without a custom metrics collector.
func setupCache[T any](t *testing.T, withCollector bool) (*Cache[T], *mockCollector) {
	t.Helper()

	var collector *mockCollector
	var c *Cache[T]
	var err error

	if withCollector {
		collector = new(mockCollector)
		c, err = NewCache[T]("test_cache", WithMetricsCollector[T](collector))
	} else {
		c, err = NewCache[T]("test_cache")
	}

	assert.NoError(t, err, "Failed to create cache")
	assert.NotNil(t, c, "Cache should not be nil")

	return c, collector
}

func TestNewLRUCache(t *testing.T) {
	t.Run("default configuration", func(t *testing.T) {
		c, _ := setupCache[int](t, false)
		assert.Equal(t, "test_cache", c.cacheName)
	})

	t.Run("with custom max cost", func(t *testing.T) {
		c, _ := setupCache[int](t, false)
		assert.NotNil(t, c)
	})

	t.Run("with metrics collector", func(t *testing.T) {
		c, collector := setupCache[int](t, true)
		assert.NotNil(t, c)
		assert.Equal(t, "test_cache", c.cacheName)
		assert.Equal(t, collector, c.evictMetrics, "Cache metrics should match the collector")
	})
}

func TestCacheSet(t *testing.T) {
	c, _ := setupCache[string](t, true)

	c.Set("key", "value")
	value, found := c.Get("key")
	assert.True(t, found, "Expected to find the key")
	assert.Equal(t, "value", value, "Expected value to match")
}

func TestCacheGet(t *testing.T) {
	c, _ := setupCache[string](t, true)

	c.Set("key", "value")

	value, found := c.Get("key")
	assert.True(t, found, "Expected to find the key")
	assert.Equal(t, "value", value, "Expected value to match")

	_, found = c.Get("non_existent")
	assert.False(t, found, "Expected not to find the key")
}

func TestCacheExists(t *testing.T) {
	c, _ := setupCache[string](t, true)

	c.Set("key", "value")

	exists := c.Exists("key")
	assert.True(t, exists, "Expected the key to exist")

	exists = c.Exists("non_existent")
	assert.False(t, exists, "Expected the key not to exist")
}

func TestCacheDelete(t *testing.T) {
	c, collector := setupCache[string](t, true)

	collector.On("RecordEviction", "test_cache").Once()

	c.Set("key", "value")

	c.Delete("key")
	collector.AssertCalled(t, "RecordEviction", "test_cache")

	_, found := c.Get("key")
	assert.False(t, found, "Expected not to find the deleted key")
}

func TestCacheClear(t *testing.T) {
	c, collector := setupCache[string](t, true)

	collector.On("RecordEviction", "test_cache").Twice()

	c.Set("key1", "value1")
	c.Set("key2", "value2")

	c.Clear()
	collector.AssertNumberOfCalls(t, "RecordEviction", 2)

	_, found1 := c.Get("key1")
	_, found2 := c.Get("key2")
	assert.False(t, found1, "Expected not to find key1 after clear")
	assert.False(t, found2, "Expected not to find key2 after clear")
}

func TestCacheCount(t *testing.T) {
	c, collector := setupCache[string](t, true)

	collector.On("RecordEviction", "test_cache").Times(3)

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	c.Set("key3", "value3")

	assert.Equal(t, 3, c.Count(), "Expected count to be 3")

	c.Delete("key2")
	assert.Equal(t, 2, c.Count(), "Expected count to be 2 after deletion")
	collector.AssertNumberOfCalls(t, "RecordEviction", 1)

	c.Clear()
	assert.Equal(t, 0, c.Count(), "Expected count to be 0 after clear")
	collector.AssertNumberOfCalls(t, "RecordEviction", 3)
}

func TestCacheKeys(t *testing.T) {
	c, collector := setupCache[string](t, true)

	collector.On("RecordEviction", "test_cache").Times(3)

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	c.Set("key3", "value3")

	keys := c.Keys()
	assert.Len(t, keys, 3, "Expected 3 keys")
	assert.ElementsMatch(t, []string{"key1", "key2", "key3"}, keys, "Keys do not match expected values")

	c.Delete("key2")
	keys = c.Keys()
	assert.Len(t, keys, 2, "Expected 2 keys after deletion")
	assert.ElementsMatch(t, []string{"key1", "key3"}, keys, "Keys do not match expected values after deletion")
	collector.AssertNumberOfCalls(t, "RecordEviction", 1)

	c.Clear()
	keys = c.Keys()
	assert.Len(t, keys, 0, "Expected no keys after clear")
	collector.AssertNumberOfCalls(t, "RecordEviction", 3)
}

func TestCacheValues(t *testing.T) {
	c, collector := setupCache[string](t, true)

	collector.On("RecordEviction", "test_cache").Times(3)

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	c.Set("key3", "value3")

	values := c.Values()
	assert.Len(t, values, 3, "Expected 3 values")
	assert.ElementsMatch(t, []string{"value1", "value2", "value3"}, values, "Values do not match expected values")

	c.Delete("key2")
	values = c.Values()
	assert.Len(t, values, 2, "Expected 2 values after deletion")
	assert.ElementsMatch(t, []string{"value1", "value3"}, values, "Values do not match expected values after deletion")
	collector.AssertNumberOfCalls(t, "RecordEviction", 1)

	c.Clear()
	values = c.Values()
	assert.Len(t, values, 0, "Expected no values after clear")
	collector.AssertNumberOfCalls(t, "RecordEviction", 3)
}

func TestCacheContents(t *testing.T) {
	c, collector := setupCache[string](t, true)

	collector.On("RecordEviction", "test_cache").Times(3)

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	c.Set("key3", "value3")

	contents := c.Contents()
	assert.Contains(t, contents, "key1", "Contents should contain key1")
	assert.Contains(t, contents, "key2", "Contents should contain key2")
	assert.Contains(t, contents, "key3", "Contents should contain key3")

	c.Delete("key2")
	contents = c.Contents()
	assert.Contains(t, contents, "key1", "Contents should contain key1")
	assert.NotContains(t, contents, "key2", "Contents should not contain key2")
	assert.Contains(t, contents, "key3", "Contents should contain key3")
	collector.AssertNumberOfCalls(t, "RecordEviction", 1)

	c.Clear()
	contents = c.Contents()
	assert.Equal(t, "[]", contents, "Contents should be empty after clear")
	collector.AssertNumberOfCalls(t, "RecordEviction", 3)
}
