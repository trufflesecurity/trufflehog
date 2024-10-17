package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockCollector struct{ mock.Mock }

func (m *mockCollector) RecordHits(cacheName string, hits uint64)     { m.Called(cacheName, hits) }
func (m *mockCollector) RecordMisses(cacheName string, misses uint64) { m.Called(cacheName, misses) }

func (m *mockCollector) RecordSet(cacheName string)    { m.Called(cacheName) }
func (m *mockCollector) RecordHit(cacheName string)    { m.Called(cacheName) }
func (m *mockCollector) RecordMiss(cacheName string)   { m.Called(cacheName) }
func (m *mockCollector) RecordDelete(cacheName string) { m.Called(cacheName) }
func (m *mockCollector) RecordClear(cacheName string)  { m.Called(cacheName) }

type mockCache[T any] struct{ mock.Mock }

func (m *mockCache[T]) Set(key string, val T) { m.Called(key, val) }

func (m *mockCache[T]) Get(key string) (T, bool) {
	args := m.Called(key)
	var zero T
	if args.Get(0) != nil {
		return args.Get(0).(T), args.Bool(1)
	}
	return zero, args.Bool(1)
}

func (m *mockCache[T]) Exists(key string) bool {
	args := m.Called(key)
	return args.Bool(0)
}

func (m *mockCache[T]) Delete(key string) { m.Called(key) }

func (m *mockCache[T]) Clear() { m.Called() }

func (m *mockCache[T]) Count() int {
	args := m.Called()
	return args.Int(0)
}

func (m *mockCache[T]) Keys() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *mockCache[T]) Values() []T {
	args := m.Called()
	return args.Get(0).([]T)
}

func (m *mockCache[T]) Contents() string {
	args := m.Called()
	return args.String(0)
}

// setupCache initializes the mock cache and metrics collector, then wraps them with the WithMetrics decorator.
func setupCache[T any](t *testing.T) (*WithMetrics[T], *mockCache[T], *mockCollector) {
	t.Helper()

	collector := new(mockCollector)
	cache := new(mockCache[T])
	wrappedCache := NewCacheWithMetrics[T](cache, collector, "test_cache")
	assert.NotNil(t, wrappedCache, "WithMetrics cache should not be nil")

	return wrappedCache, cache, collector
}

func TestNewLRUCache(t *testing.T) {
	c, _, _ := setupCache[int](t)
	assert.Equal(t, "test_cache", c.cacheName)
}

func TestCacheSet(t *testing.T) {
	c, cacheMock, collectorMock := setupCache[string](t)

	collectorMock.On("RecordSet", "test_cache").Once()
	cacheMock.On("Set", "key", "value").Once()

	c.Set("key", "value")

	collectorMock.AssertCalled(t, "RecordSet", "test_cache")
	cacheMock.AssertCalled(t, "Set", "key", "value")
}

func TestCacheGet(t *testing.T) {
	c, cacheMock, collectorMock := setupCache[string](t)

	collectorMock.On("RecordSet", "test_cache").Once()
	cacheMock.On("Set", "key", "value").Once()

	collectorMock.On("RecordHit", "test_cache").Once()
	cacheMock.On("Get", "key").Return("value", true).Once()

	collectorMock.On("RecordMiss", "test_cache").Once()
	cacheMock.On("Get", "non_existent").Return("", false).Once()

	c.Set("key", "value")
	collectorMock.AssertCalled(t, "RecordSet", "test_cache")
	cacheMock.AssertCalled(t, "Set", "key", "value")

	value, found := c.Get("key")
	assert.True(t, found, "Expected to find the key")
	assert.Equal(t, "value", value, "Expected value to match")
	collectorMock.AssertCalled(t, "RecordHit", "test_cache")
	cacheMock.AssertCalled(t, "Get", "key")

	_, found = c.Get("non_existent")
	assert.False(t, found, "Expected not to find the key")
	collectorMock.AssertCalled(t, "RecordMiss", "test_cache")
	cacheMock.AssertCalled(t, "Get", "non_existent")

	collectorMock.AssertExpectations(t)
	cacheMock.AssertExpectations(t)
}

func TestCacheExists(t *testing.T) {
	c, cacheMock, collectorMock := setupCache[string](t)

	collectorMock.On("RecordSet", "test_cache").Once()
	cacheMock.On("Set", "key", "value").Once()

	collectorMock.On("RecordHit", "test_cache").Once()
	cacheMock.On("Exists", "key").Return(true).Once()

	collectorMock.On("RecordMiss", "test_cache").Once()
	cacheMock.On("Exists", "non_existent").Return(false).Once()

	c.Set("key", "value")
	collectorMock.AssertCalled(t, "RecordSet", "test_cache")
	cacheMock.AssertCalled(t, "Set", "key", "value")

	exists := c.Exists("key")
	assert.True(t, exists, "Expected the key to exist")
	collectorMock.AssertCalled(t, "RecordHit", "test_cache")
	cacheMock.AssertCalled(t, "Exists", "key")

	exists = c.Exists("non_existent")
	assert.False(t, exists, "Expected the key not to exist")
	collectorMock.AssertCalled(t, "RecordMiss", "test_cache")
	cacheMock.AssertCalled(t, "Exists", "non_existent")

	collectorMock.AssertExpectations(t)
	cacheMock.AssertExpectations(t)
}

func TestCacheDelete(t *testing.T) {
	c, cacheMock, collectorMock := setupCache[string](t)

	collectorMock.On("RecordSet", "test_cache").Once()
	cacheMock.On("Set", "key", "value").Once()

	collectorMock.On("RecordDelete", "test_cache").Once()
	cacheMock.On("Delete", "key").Once()

	cacheMock.On("Get", "key").Return("", false).Once()

	collectorMock.On("RecordMiss", "test_cache").Once()

	c.Set("key", "value")
	collectorMock.AssertCalled(t, "RecordSet", "test_cache")
	cacheMock.AssertCalled(t, "Set", "key", "value")

	c.Delete("key")
	collectorMock.AssertCalled(t, "RecordDelete", "test_cache")
	cacheMock.AssertCalled(t, "Delete", "key")

	_, found := c.Get("key")
	assert.False(t, found, "Expected not to find the deleted key")
	collectorMock.AssertCalled(t, "RecordMiss", "test_cache")
	cacheMock.AssertCalled(t, "Get", "key")

	collectorMock.AssertExpectations(t)
	cacheMock.AssertExpectations(t)
}

func TestCacheClear(t *testing.T) {
	c, cacheMock, collectorMock := setupCache[string](t)

	collectorMock.On("RecordSet", "test_cache").Twice()
	cacheMock.On("Set", "key1", "value1").Once()
	cacheMock.On("Set", "key2", "value2").Once()

	collectorMock.On("RecordClear", "test_cache").Once()
	cacheMock.On("Clear").Once()

	cacheMock.On("Get", "key1").Return("", false).Once()
	cacheMock.On("Get", "key2").Return("", false).Once()

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	collectorMock.AssertNumberOfCalls(t, "RecordSet", 2)
	cacheMock.AssertCalled(t, "Set", "key1", "value1")
	cacheMock.AssertCalled(t, "Set", "key2", "value2")

	c.Clear()
	collectorMock.AssertCalled(t, "RecordClear", "test_cache")
	cacheMock.AssertCalled(t, "Clear")

	collectorMock.On("RecordMiss", "test_cache").Twice()
	_, found1 := c.Get("key1")
	_, found2 := c.Get("key2")
	assert.False(t, found1, "Expected not to find key1 after clear")
	assert.False(t, found2, "Expected not to find key2 after clear")
	collectorMock.AssertNumberOfCalls(t, "RecordMiss", 2)
	cacheMock.AssertCalled(t, "Get", "key1")
	cacheMock.AssertCalled(t, "Get", "key2")

	collectorMock.AssertExpectations(t)
	cacheMock.AssertExpectations(t)
}

func TestCacheCount(t *testing.T) {
	c, cacheMock, collectorMock := setupCache[string](t)

	collectorMock.On("RecordSet", "test_cache").Times(3)
	cacheMock.On("Set", mock.Anything, mock.Anything).Times(3)

	cacheMock.On("Count").Return(3).Once()

	collectorMock.On("RecordDelete", "test_cache").Once()
	cacheMock.On("Delete", "key2").Once()
	cacheMock.On("Count").Return(2).Once()

	collectorMock.On("RecordClear", "test_cache").Once()
	cacheMock.On("Clear").Once()
	cacheMock.On("Count").Return(0).Once()

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	c.Set("key3", "value3")
	assert.Equal(t, 3, c.Count(), "Expected count to be 3")
	collectorMock.AssertNumberOfCalls(t, "RecordSet", 3)
	cacheMock.AssertNumberOfCalls(t, "Set", 3)
	cacheMock.AssertCalled(t, "Count")

	c.Delete("key2")
	assert.Equal(t, 2, c.Count(), "Expected count to be 2 after deletion")
	collectorMock.AssertCalled(t, "RecordDelete", "test_cache")
	cacheMock.AssertCalled(t, "Delete", "key2")
	cacheMock.AssertCalled(t, "Count")

	c.Clear()
	assert.Equal(t, 0, c.Count(), "Expected count to be 0 after clear")
	collectorMock.AssertCalled(t, "RecordClear", "test_cache")
	cacheMock.AssertCalled(t, "Clear")
	cacheMock.AssertCalled(t, "Count")

	collectorMock.AssertExpectations(t)
	cacheMock.AssertExpectations(t)
}

func TestCacheKeys(t *testing.T) {
	c, cacheMock, collectorMock := setupCache[string](t)

	collectorMock.On("RecordSet", "test_cache").Times(3)
	cacheMock.On("Set", mock.Anything, mock.Anything).Times(3)

	collectorMock.On("RecordDelete", "test_cache").Once()
	cacheMock.On("Delete", "key2").Once()
	cacheMock.On("Clear").Once()
	collectorMock.On("RecordClear", "test_cache").Once()

	cacheMock.On("Keys").Return([]string{"key1", "key2", "key3"}).Once()
	cacheMock.On("Keys").Return([]string{"key1", "key3"}).Once()
	cacheMock.On("Keys").Return([]string{}).Once()

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	c.Set("key3", "value3")
	collectorMock.AssertNumberOfCalls(t, "RecordSet", 3)
	cacheMock.AssertNumberOfCalls(t, "Set", 3)

	keys := c.Keys()
	assert.Len(t, keys, 3, "Expected 3 keys")
	assert.ElementsMatch(t, []string{"key1", "key2", "key3"}, keys, "Keys do not match expected values")

	c.Delete("key2")
	keys = c.Keys()
	assert.Len(t, keys, 2, "Expected 2 keys after deletion")
	assert.ElementsMatch(t, []string{"key1", "key3"}, keys, "Keys do not match expected values after deletion")
	collectorMock.AssertCalled(t, "RecordDelete", "test_cache")

	c.Clear()
	keys = c.Keys()
	assert.Len(t, keys, 0, "Expected no keys after clear")
	collectorMock.AssertCalled(t, "RecordClear", "test_cache")

	collectorMock.AssertExpectations(t)
	cacheMock.AssertExpectations(t)
}

func TestCacheValues(t *testing.T) {
	c, cacheMock, collectorMock := setupCache[string](t)

	collectorMock.On("RecordSet", "test_cache").Times(3)
	cacheMock.On("Set", mock.Anything, mock.Anything).Times(3)

	collectorMock.On("RecordDelete", "test_cache").Once()
	cacheMock.On("Delete", "key2").Once()
	collectorMock.On("RecordClear", "test_cache").Once()
	cacheMock.On("Clear").Once()

	cacheMock.On("Values").Return([]string{"value1", "value2", "value3"}).Once()
	cacheMock.On("Values").Return([]string{"value1", "value3"}).Once()
	cacheMock.On("Values").Return([]string{}).Once()

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	c.Set("key3", "value3")
	collectorMock.AssertNumberOfCalls(t, "RecordSet", 3)
	cacheMock.AssertNumberOfCalls(t, "Set", 3)

	values := c.Values()
	assert.Len(t, values, 3, "Expected 3 values")
	assert.ElementsMatch(t, []string{"value1", "value2", "value3"}, values, "Values do not match expected values")

	c.Delete("key2")
	values = c.Values()
	assert.Len(t, values, 2, "Expected 2 values after deletion")
	assert.ElementsMatch(t, []string{"value1", "value3"}, values, "Values do not match expected values after deletion")
	collectorMock.AssertCalled(t, "RecordDelete", "test_cache")

	c.Clear()
	values = c.Values()
	assert.Len(t, values, 0, "Expected no values after clear")
	collectorMock.AssertCalled(t, "RecordClear", "test_cache")

	collectorMock.AssertExpectations(t)
	cacheMock.AssertExpectations(t)
}

func TestCacheContents(t *testing.T) {
	c, cacheMock, collectorMock := setupCache[string](t)

	collectorMock.On("RecordSet", "test_cache").Times(3)
	cacheMock.On("Set", mock.Anything, mock.Anything).Times(3)

	collectorMock.On("RecordDelete", "test_cache").Once()
	cacheMock.On("Delete", "key2").Once()
	collectorMock.On("RecordClear", "test_cache").Once()
	cacheMock.On("Clear").Once()

	cacheMock.On("Contents").Return("key1, key2, key3").Once()
	cacheMock.On("Contents").Return("key1, key3").Once()
	cacheMock.On("Contents").Return("[]").Once()

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	c.Set("key3", "value3")
	collectorMock.AssertNumberOfCalls(t, "RecordSet", 3)
	cacheMock.AssertNumberOfCalls(t, "Set", 3)

	contents := c.Contents()
	assert.Contains(t, contents, "key1", "Contents should contain key1")
	assert.Contains(t, contents, "key2", "Contents should contain key2")
	assert.Contains(t, contents, "key3", "Contents should contain key3")

	c.Delete("key2")
	contents = c.Contents()
	assert.Contains(t, contents, "key1", "Contents should contain key1")
	assert.NotContains(t, contents, "key2", "Contents should not contain key2")
	assert.Contains(t, contents, "key3", "Contents should contain key3")
	collectorMock.AssertCalled(t, "RecordDelete", "test_cache")

	c.Clear()
	contents = c.Contents()
	assert.Equal(t, "[]", contents, "Contents should be empty after clear")
	collectorMock.AssertCalled(t, "RecordClear", "test_cache")

	collectorMock.AssertExpectations(t)
	cacheMock.AssertExpectations(t)
}
