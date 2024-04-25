package buffer

import (
	"bytes"
	"time"
)

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
func (b *Buffer) Write(data []byte) (int, error) {
	if b.Buffer == nil {
		// This case should ideally never occur if buffers are properly managed.
		b.Buffer = bytes.NewBuffer(make([]byte, 0, defaultBufferSize))
		b.resetMetric()
	}

	size := len(data)
	bufferLength := b.Buffer.Len()
	totalSizeNeeded := bufferLength + size

	// If the total size is within the threshold, write to the buffer.
	availableSpace := b.Buffer.Cap() - bufferLength
	growSize := totalSizeNeeded - bufferLength
	if growSize > availableSpace {
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
