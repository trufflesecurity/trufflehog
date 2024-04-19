// Package bufferwritter provides a contentWriter implementation using a shared buffer pool for memory management.
package bufferwriter

import (
	"bytes"
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

// NewFromReader creates a new instance of BufferWriter and writes the content from the provided reader to the buffer.
func NewFromReader(ctx context.Context, r io.Reader) (*BufferWriter, error) {
	buf := New(ctx)
	n, err := io.Copy(buf, r)
	if err != nil {
		return nil, fmt.Errorf("error writing to buffer writer: %w", err)
	}

	ctx.Logger().V(3).Info("file written to buffer writer", "bytes", n)

	return buf, nil
}

// Write delegates the writing operation to the underlying bytes.Buffer.
func (b *BufferWriter) Write(data []byte) (int, error) {
	if b.state != writeOnly {
		return 0, fmt.Errorf("buffer must be in write-only mode to write data; current state: %d", b.state)
	}

	size := len(data)
	b.size += size
	start := time.Now()
	defer func(start time.Time) {
		bufferLength := uint64(b.buf.Len())
		b.metrics.recordDataProcessed(bufferLength, time.Since(start))

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

// readSeekCloser provides random access read, seek, and close capabilities on top of the BufferWriter.
// It combines the functionality of BufferWriter for buffered writing, bytes.Reader for random access reading and seeking,
// and adds a close method to return the buffer to the pool.
type readSeekCloser struct {
	bufWriter *BufferWriter
	reader    *bytes.Reader
}

// NewBufferReadSeekCloser initializes a readSeekCloser from an io.Reader by using
// the BufferWriter's functionality to read and store data, then setting up a bytes.Reader for random access.
// It returns the initialized readSeekCloser and any error encountered during the process.
func NewBufferReadSeekCloser(ctx context.Context, r io.Reader) (*readSeekCloser, error) {
	rdr, err := NewFromReader(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("error creating readSeekCloser: %w", err)
	}

	// Ensure that the BufferWriter is not in write mode anymore.
	if err := rdr.CloseForWriting(); err != nil {
		return nil, err
	}

	return &readSeekCloser{rdr, bytes.NewReader(rdr.buf.Bytes())}, nil
}

// Close releases the buffer back to the buffer pool.
// It should be called when the readSeekCloser is no longer needed.
// Note that closing the readSeekCloser does not affect the underlying bytes.Reader,
// which can still be used for reading, seeking, and reading at specific positions.
// Close is a no-op for the bytes.Reader.
func (b *readSeekCloser) Close() error {
	b.bufWriter.bufPool.Put(b.bufWriter.buf)
	return nil
}

// Read reads up to len(p) bytes into p from the underlying bytes.Reader.
// It returns the number of bytes read and any error encountered.
// If the bytes.Reader reaches the end of the available data, Read returns 0, io.EOF.
// It implements the io.Reader interface.
func (b *readSeekCloser) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

// Seek sets the offset for the next Read or Write operation on the underlying bytes.Reader.
// The offset is interpreted according to the whence parameter:
//   - io.SeekStart means relative to the start of the file
//   - io.SeekCurrent means relative to the current offset
//   - io.SeekEnd means relative to the end of the file
//
// Seek returns the new offset and any error encountered.
// It implements the io.Seeker interface.
func (b *readSeekCloser) Seek(offset int64, whence int) (int64, error) {
	return b.reader.Seek(offset, whence)
}

// ReadAt reads len(p) bytes from the underlying bytes.Reader starting at byte offset off.
// It returns the number of bytes read and any error encountered.
// If the bytes.Reader reaches the end of the available data before len(p) bytes are read,
// ReadAt returns the number of bytes read and io.EOF.
// It implements the io.ReaderAt interface.
func (b *readSeekCloser) ReadAt(p []byte, off int64) (n int, err error) {
	return b.reader.ReadAt(p, off)
}
