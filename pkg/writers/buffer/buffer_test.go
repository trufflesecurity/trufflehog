package buffer

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestNewBufferPool(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		opts             []PoolOpts
		expectedBuffSize uint32
	}{
		{name: "Default pool size", expectedBuffSize: defaultBufferSize},
		{
			name:             "Custom pool size",
			opts:             []PoolOpts{func(p *Pool) { p.bufferSize = 8 * 1024 }}, // 8KB
			expectedBuffSize: 8 * 1024,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pool := NewBufferPool(tc.opts...)
			assert.Equal(t, tc.expectedBuffSize, pool.bufferSize)
		})
	}
}

func TestBufferPoolGetPut(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		preparePool       func(p *Pool) *Buffer // Prepare the pool and return an initial buffer to put if needed
		expectedCapBefore int                   // Expected capacity before putting it back
		expectedCapAfter  int                   // Expected capacity after retrieving it again
	}{
		{
			name: "Get new buffer and put back without modification",
			preparePool: func(_ *Pool) *Buffer {
				return nil // No initial buffer to put
			},
			expectedCapBefore: int(defaultBufferSize),
			expectedCapAfter:  int(defaultBufferSize),
		},
		{
			name: "Put oversized buffer, expect shrink",
			preparePool: func(p *Pool) *Buffer {
				buf := &Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, 3*defaultBufferSize))}
				return buf
			},
			expectedCapBefore: int(defaultBufferSize),
			expectedCapAfter:  int(defaultBufferSize), // Should shrink back to default
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pool := NewBufferPool()
			initialBuf := tc.preparePool(pool)
			if initialBuf != nil {
				pool.Put(initialBuf)
			}

			buf := pool.Get(context.Background())
			assert.Equal(t, tc.expectedCapBefore, buf.Cap())

			pool.Put(buf)

			bufAfter := pool.Get(context.Background())
			assert.Equal(t, tc.expectedCapAfter, bufAfter.Cap())
		})
	}
}

func TestBufferWrite(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		initialCapacity   int
		writeDataSequence [][]byte // Sequence of writes to simulate multiple writes
		expectedSize      int
		expectedCap       int
	}{
		{
			name:            "Write to empty buffer",
			initialCapacity: defaultBufferSize,
			writeDataSequence: [][]byte{
				[]byte("hello"),
			},
			expectedSize: 5,
			expectedCap:  defaultBufferSize, // No growth for small data
		},
		{
			name:            "Write causing growth",
			initialCapacity: 10, // Small initial capacity to force growth
			writeDataSequence: [][]byte{
				[]byte("this is a longer string exceeding initial capacity"),
			},
			expectedSize: 50,
			expectedCap:  50,
		},
		{
			name:              "Write nil data",
			initialCapacity:   defaultBufferSize,
			writeDataSequence: [][]byte{nil},
			expectedCap:       defaultBufferSize,
		},
		{
			name:            "Repeated writes, cumulative growth",
			initialCapacity: 20, // Set an initial capacity to test growth over multiple writes
			writeDataSequence: [][]byte{
				[]byte("first write, "),
				[]byte("second write, "),
				[]byte("third write exceeding the initial capacity."),
			},
			expectedSize: 70,
			expectedCap:  70, // Expect capacity to grow to accommodate all writes
		},
		{
			name:            "Write large single data to test significant growth",
			initialCapacity: 50, // Set an initial capacity smaller than the data to be written
			writeDataSequence: [][]byte{
				bytes.Repeat([]byte("a"), 1024), // 1KB data to significantly exceed initial capacity
			},
			expectedSize: 1024,
			expectedCap:  1024,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			buf := &Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, tc.initialCapacity))}
			totalWritten := 0
			for _, data := range tc.writeDataSequence {
				n, err := buf.Write(context.Background(), data)
				assert.NoError(t, err)

				totalWritten += n
			}
			assert.Equal(t, tc.expectedSize, totalWritten)
			assert.Equal(t, tc.expectedSize, buf.Len())
			assert.GreaterOrEqual(t, buf.Cap(), tc.expectedCap)
		})
	}
}

func TestReadCloserClose(t *testing.T) {
	t.Parallel()
	onCloseCalled := false
	rc := ReadCloser([]byte("data"), func() { onCloseCalled = true })

	err := rc.Close()
	assert.NoError(t, err)
	assert.True(t, onCloseCalled, "onClose callback should be called upon Close")
}
