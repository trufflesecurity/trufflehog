package buffer

import (
	"bytes"
	"fmt"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// Buffer is a wrapper around bytes.Buffer that includes a timestamp for tracking Buffer checkout duration.
type Buffer struct {
	*bytes.Buffer
	checkedOutAt time.Time
}

// NewBuffer creates a new instance of Buffer.
func NewBuffer() *Buffer { return &Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, defaultBufferSize))} }

func (r *Buffer) Grow(size int) {
	r.Buffer.Grow(size)
	r.recordGrowth(size)
}

func (r *Buffer) resetMetric() { r.checkedOutAt = time.Now() }

func (r *Buffer) recordMetric() {
	dur := time.Since(r.checkedOutAt)
	checkoutDuration.Observe(float64(dur.Microseconds()))
	checkoutDurationTotal.Add(float64(dur.Microseconds()))
}

func (r *Buffer) recordGrowth(size int) {
	growCount.Inc()
	growAmount.Add(float64(size))
}

// Write date to the buffer.
func (r *Buffer) Write(ctx context.Context, data []byte) (int, error) {
	if r.Buffer == nil {
		// This case should ideally never occur if buffers are properly managed.
		ctx.Logger().Error(fmt.Errorf("buffer is nil, initializing a new buffer"), "action", "initializing_new_buffer")
		r.Buffer = bytes.NewBuffer(make([]byte, 0, defaultBufferSize))
		r.resetMetric()
	}

	size := len(data)
	bufferLength := r.Buffer.Len()
	totalSizeNeeded := bufferLength + size
	// If the total size is within the threshold, write to the buffer.
	ctx.Logger().V(4).Info(
		"writing to buffer",
		"data_size", size,
		"content_size", bufferLength,
	)

	availableSpace := r.Buffer.Cap() - bufferLength
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
		r.Buffer.Grow(growSize)
	}

	return r.Buffer.Write(data)
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
