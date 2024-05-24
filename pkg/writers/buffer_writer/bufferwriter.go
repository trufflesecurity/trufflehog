// Package bufferwriter provides a contentWriter implementation using a shared buffer pool for memory management.
package bufferwriter

import (
	"fmt"
	"io"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/buffers/buffer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/buffers/pool"
)

type metrics struct{}

func (metrics) recordDataProcessed(size int64, dur time.Duration) {
	writeSize.Observe(float64(size))
	totalWriteDuration.Add(float64(dur.Microseconds()))
}

const defaultBufferSize = 1 << 12 // 4KB
func init()                       { bufferPool = pool.NewBufferPool(defaultBufferSize) }

// bufferPool is the shared Buffer pool used by all BufferedFileWriters.
// This allows for efficient reuse of buffers across multiple writers.
var bufferPool *pool.Pool

// state represents the current mode of buffer.
type state uint8

const (
	// writeOnly indicates the buffer is in write-only mode.
	writeOnly state = iota
	// readOnly indicates the buffer has been closed and is in read-only mode.
	readOnly
)

// BufferWriter implements contentWriter, using a shared buffer pool for memory management.
type BufferWriter struct {
	buf     *buffer.Buffer // The current buffer in use.
	bufPool *pool.Pool     // The buffer pool used to manage the buffer.
	size    int            // The total size of the content written to the buffer.
	state   state          // The current state of the buffer.

	metrics metrics
}

// New creates a new instance of BufferWriter.
func New() *BufferWriter {
	return &BufferWriter{state: writeOnly, bufPool: bufferPool}
}

// Write delegates the writing operation to the underlying bytes.Buffer.
func (b *BufferWriter) Write(data []byte) (int, error) {
	if b.state != writeOnly {
		return 0, fmt.Errorf("buffer must be in write-only mode to write data; current state: %d", b.state)
	}
	if b.buf == nil {
		b.buf = b.bufPool.Get()
		if b.buf == nil {
			b.buf = buffer.NewBuffer()
		}
	}

	size := len(data)
	b.size += size
	start := time.Now()
	defer func(start time.Time) {
		b.metrics.recordDataProcessed(int64(size), time.Since(start))
	}(start)

	return b.buf.Write(data)
}

// ReadCloser provides a read-closer for the buffer's content.
// It wraps the buffer's content in a NopCloser to provide a ReadCloser without additional closing behavior,
// as closing a bytes.Buffer is a no-op.
func (b *BufferWriter) ReadCloser() (io.ReadCloser, error) {
	if b.state != readOnly {
		return nil, fmt.Errorf("buffer is in read-only mode")
	}
	if b.buf == nil {
		return nil, fmt.Errorf("writer buffer is nil")
	}

	return buffer.ReadCloser(b.buf.Bytes(), func() { b.bufPool.Put(b.buf) }), nil
}

// CloseForWriting is a no-op for buffer, as there is no resource cleanup needed for bytes.Buffer.
func (b *BufferWriter) CloseForWriting() error {
	b.state = readOnly
	return nil
}

// String returns the buffer's content as a string.
func (b *BufferWriter) String() (string, error) {
	if b.buf == nil {
		return "", fmt.Errorf("buffer is nil")
	}
	return b.buf.String(), nil
}

// Len returns the length of the buffer's content.
func (b *BufferWriter) Len() int { return b.size }
