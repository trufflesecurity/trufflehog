package buffer

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/writers/buffer/ring"
)

func TestBufferPoolGetPut(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		preparePool       func(p *Pool) *ring.Ring // Prepare the pool and return an initial buffer to put if needed
		expectedCapBefore int                      // Expected capacity before putting it back
		expectedCapAfter  int                      // Expected capacity after retrieving it again
	}{
		{
			name: "Get new buffer and put back without modification",
			preparePool: func(_ *Pool) *ring.Ring {
				return nil // No initial buffer to put
			},
			expectedCapBefore: int(defaultBufferSize),
			expectedCapAfter:  int(defaultBufferSize),
		},
		{
			name: "Put oversized buffer, expect shrink",
			preparePool: func(p *Pool) *ring.Ring {
				buf := ring.NewRingBuffer(3 * defaultBufferSize)
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
