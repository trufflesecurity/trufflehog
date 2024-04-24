package pool

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/buffers/buffer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
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

var (
	sharedBufferPool *Pool
	once             sync.Once
)

func initSharedBufferPool() { sharedBufferPool = NewBufferPool() }

// GetSharedBufferPool returns the shared buffer pool.
func GetSharedBufferPool() *Pool {
	once.Do(initSharedBufferPool)
	return sharedBufferPool
}

// Opts is a function that configures a BufferPool.
type Opts func(pool *Pool)

// Pool of buffers.
type Pool struct {
	*sync.Pool
	bufferSize uint32

	metrics poolMetrics
}

const defaultBufferSize = 1 << 12 // 4KB
// NewBufferPool creates a new instance of BufferPool.
func NewBufferPool(opts ...Opts) *Pool {
	pool := &Pool{bufferSize: defaultBufferSize}

	for _, opt := range opts {
		opt(pool)
	}
	pool.Pool = &sync.Pool{
		New: func() any {
			return &buffer.Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, pool.bufferSize))}
		},
	}

	return pool
}

// Get returns a Buffer from the pool.
func (p *Pool) Get(ctx context.Context) *buffer.Buffer {
	buf, ok := p.Pool.Get().(*buffer.Buffer)
	if !ok {
		ctx.Logger().Error(fmt.Errorf("Buffer pool returned unexpected type"), "using new Buffer")
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
	if buf.Cap() > maxAllowedCapacity {
		p.metrics.recordShrink(buf.Cap() - defaultBufferSize)
		buf = &buffer.Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, p.bufferSize))}
	} else {
		// Reset the Buffer to clear any existing data.
		buf.Reset()
	}

	p.Pool.Put(buf)
}
