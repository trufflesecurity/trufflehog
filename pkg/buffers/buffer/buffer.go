// Package buffer provides a custom buffer type that includes metrics for tracking buffer usage.
// It also provides a pool for managing buffer reusability.
package buffer

import (
	"bytes"
	"io"
	"time"
)

// Buffer is a wrapper around bytes.Buffer that includes a timestamp for tracking Buffer checkout duration.
type Buffer struct {
	*bytes.Buffer
	checkedOutAt time.Time
}

const defaultBufferSize = 1 << 12 // 4KB
// NewBuffer creates a new instance of Buffer.
func NewBuffer() *Buffer { return &Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, defaultBufferSize))} }

func (b *Buffer) Grow(size int) {
	b.Buffer.Grow(size)
	b.recordGrowth(size)
}

func (b *Buffer) ResetMetric() { b.checkedOutAt = time.Now() }

func (b *Buffer) RecordMetric() {
	dur := time.Since(b.checkedOutAt)
	checkoutDuration.Observe(float64(dur.Microseconds()))
	checkoutDurationTotal.Add(float64(dur.Microseconds()))
	totalBufferSize.Add(float64(b.Cap()))
	totalBufferLength.Add(float64(b.Len()))
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
		b.ResetMetric()
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
		b.Grow(growSize)
	}

	return b.Buffer.Write(data)
}

// Compile time check to make sure readCloser implements io.ReadSeekCloser.
var _ io.ReadSeekCloser = (*readCloser)(nil)

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
	brc.Reader = nil
	return nil
}

// Read reads up to len(p) bytes into p from the underlying reader.
// It returns the number of bytes read and any error encountered.
// On reaching the end of the available data, it returns 0 and io.EOF.
// Calling Read on a closed reader will also return 0 and io.EOF.
func (brc *readCloser) Read(p []byte) (int, error) {
	if brc.Reader == nil {
		return 0, io.EOF
	}

	return brc.Reader.Read(p)
}
