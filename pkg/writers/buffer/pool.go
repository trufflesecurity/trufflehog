package buffer

import (
	"fmt"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/writers/buffer/ring"
)

type poolMetrics struct{}

func (poolMetrics) recordShrink(amount int) {
	shrinkCount.Inc()
	shrinkAmount.Add(float64(amount))
}

func (poolMetrics) recordBufferRetrival() {
	activeBufferCount.Inc()
	checkoutCount.Inc()
	bufferCount.Inc()
}

func (poolMetrics) recordBufferReturn(bufCap, bufLen int64) {
	activeBufferCount.Dec()
	totalBufferSize.Add(float64(bufCap))
	totalBufferLength.Add(float64(bufLen))
}

// PoolOpts is a function that configures a BufferPool.
type PoolOpts func(pool *Pool)

// Pool of buffers.
type Pool struct {
	*sync.Pool
	bufferSize uint32

	metrics poolMetrics
}

const defaultBufferSize = 1 << 12 // 4KB
// NewBufferPool creates a new instance of BufferPool.
func NewBufferPool(opts ...PoolOpts) *Pool {
	pool := &Pool{bufferSize: defaultBufferSize}

	for _, opt := range opts {
		opt(pool)
	}
	pool.Pool = &sync.Pool{
		New: func() any {
			return ring.NewRingBuffer(int(pool.bufferSize))
		},
	}

	return pool
}

// Get returns a Buffer from the pool.
func (p *Pool) Get(ctx context.Context) *ring.Ring {
	buf, ok := p.Pool.Get().(*ring.Ring)
	if !ok {
		ctx.Logger().Error(fmt.Errorf("buffer pool returned unexpected type"), "using new Buffer")
		buf = ring.NewRingBuffer(int(p.bufferSize))
	}
	p.metrics.recordBufferRetrival()

	return buf
}

// Put returns a Buffer to the pool.
func (p *Pool) Put(buf *ring.Ring) {
	p.metrics.recordBufferReturn(int64(buf.Cap()), int64(buf.Len()))

	// If the Buffer is more than twice the default size, replace it with a new Buffer.
	// This prevents us from returning very large buffers to the pool.
	const maxAllowedCapacity = 2 * defaultBufferSize
	if buf.Cap() > maxAllowedCapacity {
		p.metrics.recordShrink(buf.Cap() - defaultBufferSize)
		buf = ring.NewRingBuffer(int(p.bufferSize))
	} else {
		buf.Reset()
	}

	p.Pool.Put(buf)
}
