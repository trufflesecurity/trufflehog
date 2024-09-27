package sizedlru

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type mockCollector struct{ mock.Mock }

func (m *mockCollector) RecordHits(cacheName string, hits uint64) { m.Called(cacheName, hits) }

func (m *mockCollector) RecordMisses(cacheName string, misses uint64) { m.Called(cacheName, misses) }

func (m *mockCollector) RecordEviction(cacheName string) { m.Called(cacheName) }

func (m *mockCollector) RecordSet(cacheName string) { m.Called(cacheName) }

func (m *mockCollector) RecordHit(cacheName string) { m.Called(cacheName) }

func (m *mockCollector) RecordMiss(cacheName string) { m.Called(cacheName) }

func (m *mockCollector) RecordDelete(cacheName string) { m.Called(cacheName) }

func (m *mockCollector) RecordClear(cacheName string) { m.Called(cacheName) }

// setupCache initializes the metrics and cache.
// If withCollector is true, it sets up a cache with a custom metrics collector.
// Otherwise, it sets up a cache without a custom metrics collector.
func setupCache[T any](t *testing.T, withCollector bool) (*Cache[T], *mockCollector) {
	t.Helper()

	// Call InitializeMetrics first.
	cache.InitializeMetrics(common.MetricsNamespace, common.MetricsSubsystem)

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
		assert.NotNil(t, c.metrics, "Cache metrics should not be nil")
	})

	t.Run("with custom max cost", func(t *testing.T) {
		c, _ := setupCache[int](t, false)
		assert.NotNil(t, c)
	})

	t.Run("with metrics collector", func(t *testing.T) {
		c, collector := setupCache[int](t, true)
		assert.NotNil(t, c)
		assert.Equal(t, "test_cache", c.cacheName)
		assert.Equal(t, collector, c.metrics, "Cache metrics should match the collector")
	})
}

func TestCacheSet(t *testing.T) {
	c, collector := setupCache[string](t, true)

	collector.On("RecordSet", "test_cache").Once()
	c.Set("key", "value")

	collector.AssertCalled(t, "RecordSet", "test_cache")
}

func TestCacheGet(t *testing.T) {
	c, collector := setupCache[string](t, true)

	collector.On("RecordSet", "test_cache").Once()
	collector.On("RecordHit", "test_cache").Once()
	collector.On("RecordMiss", "test_cache").Once()

	c.Set("key", "value")
	collector.AssertCalled(t, "RecordSet", "test_cache")

	value, found := c.Get("key")
	assert.True(t, found, "Expected to find the key")
	assert.Equal(t, "value", value, "Expected value to match")
	collector.AssertCalled(t, "RecordHit", "test_cache")

	_, found = c.Get("non_existent")
	assert.False(t, found, "Expected not to find the key")
	collector.AssertCalled(t, "RecordMiss", "test_cache")
}

func TestCacheExists(t *testing.T) {
	c, collector := setupCache[string](t, true)

	collector.On("RecordSet", "test_cache").Once()
	collector.On("RecordHit", "test_cache").Twice()
	collector.On("RecordMiss", "test_cache").Once()

	c.Set("key", "value")
	collector.AssertCalled(t, "RecordSet", "test_cache")

	exists := c.Exists("key")
	assert.True(t, exists, "Expected the key to exist")
	collector.AssertCalled(t, "RecordHit", "test_cache")

	exists = c.Exists("non_existent")
	assert.False(t, exists, "Expected the key not to exist")
	collector.AssertCalled(t, "RecordMiss", "test_cache")
}

func TestCacheDelete(t *testing.T) {
	c, collector := setupCache[string](t, true)

	collector.On("RecordSet", "test_cache").Once()
	collector.On("RecordDelete", "test_cache").Once()
	collector.On("RecordMiss", "test_cache").Once()
	collector.On("RecordEviction", "test_cache").Once()

	c.Set("key", "value")
	collector.AssertCalled(t, "RecordSet", "test_cache")

	c.Delete("key")
	collector.AssertCalled(t, "RecordDelete", "test_cache")
	collector.AssertCalled(t, "RecordEviction", "test_cache")

	_, found := c.Get("key")
	assert.False(t, found, "Expected not to find the deleted key")
	collector.AssertCalled(t, "RecordMiss", "test_cache")
}

func TestCacheClear(t *testing.T) {
	c, collector := setupCache[string](t, true)

	collector.On("RecordSet", "test_cache").Twice()
	collector.On("RecordClear", "test_cache").Once()
	collector.On("RecordMiss", "test_cache").Twice()
	collector.On("RecordEviction", "test_cache").Twice()

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	collector.AssertNumberOfCalls(t, "RecordSet", 2)

	c.Clear()
	collector.AssertCalled(t, "RecordClear", "test_cache")
	collector.AssertNumberOfCalls(t, "RecordEviction", 2)

	_, found1 := c.Get("key1")
	_, found2 := c.Get("key2")
	assert.False(t, found1, "Expected not to find key1 after clear")
	assert.False(t, found2, "Expected not to find key2 after clear")
	collector.AssertNumberOfCalls(t, "RecordMiss", 2)
}
