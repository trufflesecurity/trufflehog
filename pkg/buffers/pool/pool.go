package pool

import (
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/buffers/buffer"
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

func (poolMetrics) recordBufferReturn(buf *buffer.CheckoutBuffer) {
	activeBufferCount.Dec()
	buf.RecordMetric()
}

// Pool of buffers.
type Pool struct {
	*sync.Pool

	metrics poolMetrics
}

// const defaultBufferSize = 1 << 12 // 4KB
const defaultBufferSize = 1 << 16 // 64KB
// NewBufferPool creates a new instance of BufferPool.
func NewBufferPool(opts ...buffer.Option) *Pool {
	pool := new(Pool)

	buf := buffer.NewBuffer(opts...)
	pool.Pool = &sync.Pool{
		New: func() any { return buf },
	}

	return pool
}

// Get returns a CheckoutBuffer from the pool.
func (p *Pool) Get() *buffer.CheckoutBuffer {
	buf, ok := p.Pool.Get().(*buffer.CheckoutBuffer)
	if !ok {
		buf = buffer.NewBuffer()
	}
	p.metrics.recordBufferRetrival()
	buf.ResetMetric()

	return buf
}

// Put returns a CheckoutBuffer to the pool.
func (p *Pool) Put(buf *buffer.CheckoutBuffer) {
	p.metrics.recordBufferReturn(buf)

	// If the CheckoutBuffer is more than twice the default size, replace it with a new CheckoutBuffer.
	// This prevents us from returning very large buffers to the pool.
	const maxAllowedCapacity = 2 * defaultBufferSize
	if buf.Cap() > maxAllowedCapacity {
		p.metrics.recordShrink(buf.Cap() - defaultBufferSize)
		buf = buffer.NewBuffer()
	} else {
		// Reset the CheckoutBuffer to clear any existing data.
		buf.Reset()
	}

	p.Pool.Put(buf)
}
