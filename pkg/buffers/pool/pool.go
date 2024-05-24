package pool

import (
	"bytes"
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

func (poolMetrics) recordBufferReturn(buf *buffer.Buffer) {
	activeBufferCount.Dec()
	buf.RecordMetric()
}

// Pool of buffers.
type Pool struct {
	*sync.Pool
	bufferSize int

	metrics poolMetrics
}

const defaultBufferSize = 1 << 12 // 4KB
// NewBufferPool creates a new instance of BufferPool.
func NewBufferPool(size int) *Pool {
	pool := &Pool{bufferSize: size}

	pool.Pool = &sync.Pool{
		New: func() any {
			return &buffer.Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, pool.bufferSize))}
		},
	}

	return pool
}

// Get returns a Buffer from the pool.
func (p *Pool) Get() *buffer.Buffer {
	buf, ok := p.Pool.Get().(*buffer.Buffer)
	if !ok {
		buf = &buffer.Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, p.bufferSize))}
	}
	p.metrics.recordBufferRetrival()
	buf.ResetMetric()

	return buf
}

// Put returns a Buffer to the pool.
func (p *Pool) Put(buf *buffer.Buffer) {
	p.metrics.recordBufferReturn(buf)

	// If the Buffer is more than twice the default size, replace it with a new Buffer.
	// This prevents us from returning very large buffers to the pool.
	const maxAllowedCapacity = 2 * defaultBufferSize
	if buf.Cap() > int(maxAllowedCapacity) {
		p.metrics.recordShrink(buf.Cap() - defaultBufferSize)
		buf = &buffer.Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, p.bufferSize))}
	} else {
		// Reset the Buffer to clear any existing data.
		buf.Reset()
	}

	p.Pool.Put(buf)
}
