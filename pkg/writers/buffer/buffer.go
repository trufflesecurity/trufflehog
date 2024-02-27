// Package buffer provides a custom buffer type that includes metrics for tracking buffer usage.
// It also provides a pool for managing buffer reusability.
package buffer

import (
	"bytes"
	"fmt"
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

func (poolMetrics) recordBufferReturn(bufCap, bufLen int64) {
	activeBufferCount.Dec()
	totalBufferSize.Add(float64(bufCap))
	totalBufferLength.Add(float64(bufLen))
}

// SizedBufferPool manages a pool of Buffer objects using a bounded channel. Each Buffer is pre-allocated
// with a specified size to optimize memory usage and reduce runtime allocations. This pool aims to
// balance memory efficiency with the flexibility of handling varying buffer sizes as needed.
//
// This implementation of SizedBufferPool is inspired by the bpool package.
// Original source: https://pkg.go.dev/github.com/oxtoacart/bpool#section-readme
// We adapted the original implementation to fit our custom Buffer type and specific requirements.
type SizedBufferPool struct {
	c          chan *Buffer // Channel of pooled Buffer objects.
	poolSize   int          // The maximum number of Buffer objects allowed in the pool.
	bufferSize int          // The initial capacity for each new Buffer in the pool.

	metrics poolMetrics // Metrics tracking the performance and usage of the buffer pool.
}

// PoolOpts is a configuration function used to set options on a SizedBufferPool instance.
type PoolOpts func(pool *SizedBufferPool)

// WithPoolBufferSize configures the initial capacity for all new buffers created by the pool.
// This size should be chosen based on typical usage patterns to minimize the need for dynamic buffer resizing.
func WithPoolBufferSize(size int) PoolOpts {
	return func(pool *SizedBufferPool) { pool.bufferSize = size }
}

// WithPoolSize specifies the maximum number of buffers that the pool can hold.
// This limit helps in controlling the memory footprint of the application.
func WithPoolSize(size int) PoolOpts { return func(pool *SizedBufferPool) { pool.poolSize = size } }

const (
	defaultBufferSize = 1 << 12 // 4KB
	defaultPoolSize   = 1 << 10 // 1024
)

// NewSizedBufferPool initializes a new instance of SizedBufferPool with optional configurations.
// It pre-allocates a pool of buffers to a specified size (poolSize) and sets each buffer's
// initial capacity (bufferSize) to reduce the frequency of runtime allocations.
// The options allow for customization of the pool according to application-specific requirements,
// optimizing for the common case of buffer usage.
//
// The value of bufferSize should seek to provide a buffer that is representative of
// most data written to the the buffer (i.e. 95th percentile) without being
// overly large (which will increase static memory consumption).
func NewSizedBufferPool(opts ...PoolOpts) (bp *SizedBufferPool) {
	pool := &SizedBufferPool{
		c:          make(chan *Buffer, defaultPoolSize),
		poolSize:   defaultPoolSize,
		bufferSize: defaultBufferSize,
	}

	for _, opt := range opts {
		opt(pool)
	}

	return pool
}

// Get retrieves a Buffer from the pool or creates a new one if the pool is empty.
// This method ensures that a Buffer is always available for use, with a pre-allocated
// capacity set according to the pool's configuration.
func (bp *SizedBufferPool) Get() (b *Buffer) {
	select {
	case b = <-bp.c:
	// Reuse existing buffer.
	default:
		// Create new buffer.
		b = NewBuffer(WithBufferSize(bp.poolSize))
	}

	bp.metrics.recordBufferRetrival()
	b.resetMetric()
	return
}

// Put returns a Buffer to the pool for reuse. If the pool is full, or if the Buffer's
// capacity significantly exceeds the pool's default buffer size, the Buffer is discarded
// to avoid holding onto large amounts of memory. This method also resets the Buffer before
// returning it to the pool, ensuring that it is ready for immediate reuse without leaking
// any previous content.
func (bp *SizedBufferPool) Put(b *Buffer) {
	b.Reset()

	// Calculate the capacity of the buffer. If it's more than twice the pool's default size,
	// create a new buffer to prevent excessive memory retention.
	// Note that the cap(b.Bytes()) provides the capacity from the read off-set
	// only, but as we've called b.Reset() the full capacity of the underlying
	// byte slice is returned.
	capacity := cap(b.Bytes())
	bp.metrics.recordBufferReturn(int64(capacity), int64(b.Len()))
	const maxAllowedCapacity = 2 * defaultBufferSize
	if capacity > maxAllowedCapacity {
		bp.metrics.recordShrink(capacity - defaultBufferSize)
		b = NewBuffer(WithBufferSize(bp.bufferSize))
	}

	// Attempt to return the buffer to the pool. If the pool is full, discard the buffer.
	select {
	case bp.c <- b:
	default:
	}
}

// Buffer is a wrapper around bytes.Buffer that includes a timestamp for tracking Buffer checkout duration.
type Buffer struct {
	*bytes.Buffer
	checkedOutAt time.Time
}

// Option is a function that configures a Buffer.
type Option func(*Buffer)

// WithBufferSize sets the initial capacity of the buffer.
func WithBufferSize(size int) Option {
	return func(b *Buffer) { b.Buffer = bytes.NewBuffer(make([]byte, 0, size)) }
}

// NewBuffer creates a new instance of Buffer.
func NewBuffer(opts ...Option) *Buffer {
	b := &Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, defaultBufferSize))}
	for _, opt := range opts {
		opt(b)
	}

	return b
}

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
		b.Buffer.Grow(growSize)
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
