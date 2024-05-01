// Package buffer provides a custom buffer type that includes metrics for tracking buffer usage.
// It also provides a pool for managing buffer reusability.
package buffer

import (
	"bytes"
	"io"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/buffers/buffer/ring"
)

type Buffer interface {
	io.ReadWriter
	io.WriterTo
	Len() int
	Cap() int
	Reset()
	Grow(int)
	Bytes() []byte
	String() string
}

// CheckoutBuffer is a wrapper around bytes.Buffer that includes a timestamp for tracking CheckoutBuffer checkout duration.
type CheckoutBuffer struct {
	Buffer
	checkedOutAt time.Time
}

const defaultBufferSize = 1 << 12 // 4KB

// WithBuffer is a functional option to specify a custom buffer.
func WithBuffer(b Buffer) func(*CheckoutBuffer) {
	return func(cb *CheckoutBuffer) {
		cb.Buffer = b
	}
}

// Option is a functional option to configure a CheckoutBuffer.
type Option func(*CheckoutBuffer)

// NewBuffer creates a new instance of CheckoutBuffer.
func NewBuffer(opts ...Option) *CheckoutBuffer {
	buf := new(CheckoutBuffer)
	for _, opt := range opts {
		opt(buf)
	}
	if buf.Buffer == nil {
		buf.Buffer = ring.NewBuffer(defaultBufferSize)
	}

	return buf
}

func (b *CheckoutBuffer) Grow(size int) {
	b.Buffer.Grow(size)
	b.recordGrowth(size)
}

func (b *CheckoutBuffer) ResetMetric() { b.checkedOutAt = time.Now() }

func (b *CheckoutBuffer) RecordMetric() {
	dur := time.Since(b.checkedOutAt)
	checkoutDuration.Observe(float64(dur.Microseconds()))
	checkoutDurationTotal.Add(float64(dur.Microseconds()))
	totalBufferSize.Add(float64(b.Cap()))
	totalBufferLength.Add(float64(b.Len()))
}

func (b *CheckoutBuffer) recordGrowth(size int) {
	growCount.Inc()
	growAmount.Add(float64(size))
}

// Write date to the Buffer.
func (b *CheckoutBuffer) Write(data []byte) (int, error) {
	if b.Buffer == nil {
		// This case should ideally never occur if buffers are properly managed.
		b.Buffer = ring.NewBuffer(defaultBufferSize)
		b.ResetMetric()
	}

	size := len(data)
	bufferLength := b.Buffer.Len()
	totalSizeNeeded := bufferLength + size

	// If the total size is within the threshold, write to the Buffer.
	availableSpace := b.Buffer.Cap() - bufferLength
	growSize := totalSizeNeeded - bufferLength
	if growSize > availableSpace {
		// We are manually growing the Buffer so we can track the growth via metrics.
		// Knowing the exact data size, we directly resize to fit it, rather than exponential growth
		// which may require multiple allocations and copies if the size required is much larger
		// than double the capacity. Our approach aligns with default behavior when growth sizes
		// happen to match current capacity, retaining asymptotic efficiency benefits.
		b.Grow(growSize)
	}

	return b.Buffer.Write(data)
}

// readCloser is a custom implementation of io.ReadCloser. It wraps a bytes.Reader
// for reading data from an in-memory Buffer and includes an onClose callback.
// The onClose callback is used to return the Buffer to the pool, ensuring Buffer re-usability.
type readCloser struct {
	*bytes.Reader
	onClose func()
}

// ReadCloser creates a new instance of readCloser.
func ReadCloser(data []byte, onClose func()) *readCloser {
	return &readCloser{Reader: bytes.NewReader(data), onClose: onClose}
}

// Close implements the io.Closer interface. It calls the onClose callback to return the Buffer
// to the pool, enabling Buffer reuse. This method should be called by the consumers of ReadCloser
// once they have finished reading the data to ensure proper resource management.
func (brc *readCloser) Close() error {
	if brc.onClose == nil {
		return nil
	}

	brc.onClose() // Return the Buffer to the pool
	return nil
}
