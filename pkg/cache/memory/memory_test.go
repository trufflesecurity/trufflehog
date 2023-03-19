package memory

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCache(t *testing.T) {
	c := New()

	// Test set and get.
	c.Set("key1", true)
	v, ok := c.Get("key1")
	if !ok {
		t.Fatalf("Unexpected value for key1: %v, %v", v, ok)
	}

	// Test the count.
	if c.Count() != 1 {
		t.Fatalf("Unexpected count: %d", c.Count())
	}

	// Test delete.
	c.Delete("key1")
	v, ok = c.Get("key1")
	if ok {
		t.Fatalf("Unexpected value for key1 after delete: %v, %v", v, ok)
	}

	// Test clear.
	c.Clear()
	v, ok = c.Get("key10")
	if ok || v != "" {
		t.Fatalf("Unexpected value for key10 after clear: %v, %v", v, ok)
	}

	// Test contents.
	keys := []string{"key1", "key2", "key3"}
	for _, k := range keys {
		c.Set(k, true)
	}

	items := c.Contents()
	sort.Strings(keys)
	res := strings.Split(items, ",")
	sort.Strings(res)

	if len(keys) != len(res) {
		t.Fatalf("Unexpected length of items: %d", len(res))
	}
	if !cmp.Equal(keys, res) {
		t.Fatalf("Unexpected items: %v", res)
	}
}

func setupBenchmarks(b *testing.B) *Cache {
	b.Helper()

	c := New()

	for i := 0; i < 500_000; i++ {
		key := fmt.Sprintf("key%d", i)
		c.Set(key, true)
	}

	return c
}

func BenchmarkSet(b *testing.B) {
	c := New()

	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key%d", i)
		c.Set(key, true)
	}
}

func BenchmarkGet(b *testing.B) {
	c := setupBenchmarks(b)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key%d", i)
		c.Get(key)
	}
}

func BenchmarkDelete(b *testing.B) {
	c := setupBenchmarks(b)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key%d", i)
		c.Delete(key)
	}
}

func BenchmarkCount(b *testing.B) {
	c := setupBenchmarks(b)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Count()
	}
}

func BenchmarkContents(b *testing.B) {
	c := setupBenchmarks(b)
	b.ResetTimer()

	var s string

	for i := 0; i < b.N; i++ {
		s = c.Contents()
	}

	_ = s
}
