// Package buffer provides a custom buffer type that includes metrics for tracking buffer usage.
// It also provides a pool for managing buffer reusability.
package buffer

import (
	"bytes"
	"fmt"
	"sync"
	"time"

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

func (poolMetrics) recordBufferReturn(buf *Buffer) {
	activeBufferCount.Dec()
	totalBufferSize.Add(float64(buf.Len()))
	totalBufferLength.Add(float64(buf.Len()))
	buf.recordMetric()
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
			return &Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, pool.bufferSize))}
		},
	}

	return pool
}

// Get returns a Buffer from the pool.
func (p *Pool) Get(ctx context.Context) *Buffer {
	buf, ok := p.Pool.Get().(*Buffer)
	if !ok {
		ctx.Logger().Error(fmt.Errorf("Buffer pool returned unexpected type"), "using new Buffer")
		buf = &Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, p.bufferSize))}
	}
	p.metrics.recordBufferRetrival()
	buf.resetMetric()

	return buf
}

// Put returns a Buffer to the pool.
func (p *Pool) Put(buf *Buffer) {
	p.metrics.recordBufferReturn(buf)

	// If the Buffer is more than twice the default size, replace it with a new Buffer.
	// This prevents us from returning very large buffers to the pool.
	const maxAllowedCapacity = 2 * defaultBufferSize
	if buf.Cap() > maxAllowedCapacity {
		p.metrics.recordShrink(buf.Cap() - defaultBufferSize)
		buf = &Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, p.bufferSize))}
	} else {
		// Reset the Buffer to clear any existing data.
		buf.Reset()
	}

	p.Pool.Put(buf)
}

// Buffer is a wrapper around bytes.Buffer that includes a timestamp for tracking Buffer checkout duration.
type Buffer struct {
	*bytes.Buffer
	checkedOutAt time.Time
}

// NewBuffer creates a new instance of Buffer.
func NewBuffer() *Buffer { return &Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, defaultBufferSize))} }

func (b *Buffer) Grow(size int) {
	b.Buffer.Grow(size)
	b.recordGrowth(size)
}

func (b *Buffer) resetMetric() { b.checkedOutAt = time.Now() }

func (b *Buffer) recordMetric() {
	dur := time.Since(b.checkedOutAt)
	checkoutDuration.Observe(float64(dur.Microseconds()))
	checkoutDurationTotal.Add(float64(dur.Microseconds()))
}

func (b *Buffer) recordGrowth(size int) {
	growCount.Inc()
	growAmount.Add(float64(size))
}

// Write date to the buffer.
func (b *Buffer) Write(ctx context.Context, data []byte) (int, error) {
	if b.Buffer == nil {
		// This case should ideally never occur if buffers are properly managed.
		ctx.Logger().Error(fmt.Errorf("buffer is nil, initializing a new buffer"), "action", "initializing_new_buffer")
		b.Buffer = bytes.NewBuffer(make([]byte, 0, defaultBufferSize))
		b.resetMetric()
	}

	size := len(data)
	bufferLength := b.Buffer.Len()
	totalSizeNeeded := bufferLength + size
	// If the total size is within the threshold, write to the buffer.
	ctx.Logger().V(4).Info(
		"writing to buffer",
		"data_size", size,
		"content_size", bufferLength,
	)

	availableSpace := b.Buffer.Cap() - bufferLength
	growSize := totalSizeNeeded - bufferLength
	if growSize > availableSpace {
		ctx.Logger().V(4).Info(
			"buffer size exceeded, growing buffer",
			"current_size", bufferLength,
			"new_size", totalSizeNeeded,
			"available_space", availableSpace,
			"grow_size", growSize,
		)
		// We are manually growing the buffer so we can track the growth via metrics.
		// Knowing the exact data size, we directly resize to fit it, rather than exponential growth
		// which may require multiple allocations and copies if the size required is much larger
		// than double the capacity. Our approach aligns with default behavior when growth sizes
		// happen to match current capacity, retaining asymptotic efficiency benefits.
		b.Grow(growSize)
	}

	return b.Buffer.Write(data)
}

// readCloser is a custom implementation of io.ReadCloser. It wraps a bytes.Reader
// for reading data from an in-memory buffer and includes an onClose callback.
// The onClose callback is used to return the buffer to the pool, ensuring buffer re-usability.
type readCloser struct {
	*bytes.Reader
	onClose func()
}

// ReadCloser creates a new instance of readCloser.
func ReadCloser(data []byte, onClose func()) *readCloser {
	return &readCloser{Reader: bytes.NewReader(data), onClose: onClose}
}

// Close implements the io.Closer interface. It calls the onClose callback to return the buffer
// to the pool, enabling buffer reuse. This method should be called by the consumers of ReadCloser
// once they have finished reading the data to ensure proper resource management.
func (brc *readCloser) Close() error {
	if brc.onClose == nil {
		return nil
	}

	brc.onClose() // Return the buffer to the pool
	return nil
}
