package pool

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/buffers/buffer"
)

func TestNewBufferPool(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		opts             []Opts
		expectedBuffSize uint32
	}{
		{name: "Default pool size", expectedBuffSize: defaultBufferSize},
		{
			name:             "Custom pool size",
			opts:             []Opts{func(p *Pool) { p.bufferSize = 8 * 1024 }}, // 8KB
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
		preparePool       func(p *Pool) *buffer.CheckoutBuffer // Prepare the pool and return an initial buffer to put if needed
		expectedCapBefore int                                  // Expected capacity before putting it back
		expectedCapAfter  int                                  // Expected capacity after retrieving it again
	}{
		{
			name: "Get new buffer and put back without modification",
			preparePool: func(_ *Pool) *buffer.CheckoutBuffer {
				return nil // No initial buffer to put
			},
			expectedCapBefore: int(defaultBufferSize),
			expectedCapAfter:  int(defaultBufferSize),
		},
		{
			name: "Put oversized buffer, expect shrink",
			preparePool: func(p *Pool) *buffer.CheckoutBuffer {
				buf := &buffer.CheckoutBuffer{Buffer: bytes.NewBuffer(make([]byte, 0, 3*defaultBufferSize))}
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

			buf := pool.Get()
			assert.Equal(t, tc.expectedCapBefore, buf.Cap())

			pool.Put(buf)

			bufAfter := pool.Get()
			assert.Equal(t, tc.expectedCapAfter, bufAfter.Cap())
		})
	}
}
