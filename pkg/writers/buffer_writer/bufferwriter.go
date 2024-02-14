// Package bufferwritter provides a contentWriter implementation using a shared buffer pool for memory management.
package bufferwriter

import (
	"fmt"
	"io"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/writers/buffer"
)

type metrics struct{}

func (metrics) recordDataProcessed(size uint64, dur time.Duration) {
	totalWriteSize.Add(float64(size))
	totalWriteDuration.Add(float64(dur.Microseconds()))
}

func init() { bufferPool = buffer.NewBufferPool() }

// bufferPool is the shared Buffer pool used by all BufferedFileWriters.
// This allows for efficient reuse of buffers across multiple writers.
var bufferPool *buffer.Pool

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
	bufPool *buffer.Pool   // The buffer pool used to manage the buffer.
	size    int            // The total size of the content written to the buffer.
	state   state          // The current state of the buffer.

	metrics metrics
}

// New creates a new instance of BufferWriter.
func New(ctx context.Context) *BufferWriter {
	buf := bufferPool.Get(ctx)
	if buf == nil {
		buf = buffer.NewBuffer()
	}
	return &BufferWriter{buf: buf, state: writeOnly, bufPool: bufferPool}
}

// Write delegates the writing operation to the underlying bytes.Buffer, ignoring the context.
// The context is included to satisfy the contentWriter interface, allowing for future extensions
// where context handling might be necessary (e.g., for timeouts or cancellation).
func (b *BufferWriter) Write(ctx context.Context, data []byte) (int, error) {
	if b.state != writeOnly {
		return 0, fmt.Errorf("buffer must be in write-only mode to write data; current state: %d", b.state)
	}

	size := len(data)
	b.size += size
	start := time.Now()
	defer func(start time.Time) {
		bufferLength := uint64(b.buf.Len())
		b.metrics.recordDataProcessed(bufferLength, time.Since(start))

		ctx.Logger().V(4).Info(
			"write complete",
			"data_size", size,
			"buffer_len", bufferLength,
			"buffer_size", b.buf.Cap(),
		)
	}(start)
	return b.buf.Write(ctx, data)
}

// ReadCloser provides a read-closer for the buffer's content.
// It wraps the buffer's content in a NopCloser to provide a ReadCloser without additional closing behavior,
// as closing a bytes.Buffer is a no-op.
func (b *BufferWriter) ReadCloser() (io.ReadCloser, error) {
	if b.state != readOnly {
		return nil, fmt.Errorf("buffer is in read-only mode")
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
