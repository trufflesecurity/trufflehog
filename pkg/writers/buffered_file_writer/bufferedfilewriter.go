// Package bufferedfilewriter provides a writer that buffers data in memory until a threshold is exceeded at
// which point it switches to writing to a temporary file.
package bufferedfilewriter

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type bufferPoolMetrics struct {
	growCount    atomic.Int64
	growAmount   atomic.Int64
	shrinkAmount atomic.Int64

	activeBufferCount atomic.Int64
	bufferCount       atomic.Int64

	totalBufferLength atomic.Int64
	totalBufferSize   atomic.Int64

	preAllocatedUse atomic.Int64 // Tracks successful uses of pre-allocated buffers
	newBufferCount  atomic.Int64
}

func ReportBufferPoolMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			sharedBufferPool.metrics.print()
		}
	}
}

func (m *bufferPoolMetrics) recordGrowth(growthAmount int) {
	m.growCount.Add(1)
	m.newBufferCount.Add(1)
	m.growAmount.Add(int64(growthAmount))
}

func (m *bufferPoolMetrics) averageGrowth() int64 {
	if m.growCount.Load() == 0 {
		return 0
	}
	return m.growAmount.Load() / m.growCount.Load()
}

// recordBufferRetrival groups the metrics updates for when a buffer is fetched.
func (m *bufferPoolMetrics) recordBufferRetrival(bufCap, bufLen int64) {
	m.activeBufferCount.Add(1)
	m.bufferCount.Add(1)
	m.totalBufferSize.Add(bufCap)
	m.totalBufferLength.Add(bufLen)
}

// recordBufferReturn groups the metrics updates for when a buffer is returned.
func (m *bufferPoolMetrics) recordBufferReturn() { m.activeBufferCount.Add(-1) }

func (m *bufferPoolMetrics) recordPreAllocatedUse() { m.preAllocatedUse.Add(1) }

// print returns a string representation of the buffer pool metrics.
func (m *bufferPoolMetrics) print() {
	fmt.Printf("Buffer Pool Metrics:\n")
	fmt.Printf("Active Buffers: %d\n", m.activeBufferCount.Load())
	fmt.Printf("Buffer Count: %d\n", m.bufferCount.Load())
	fmt.Printf("Total Buffer Length: %d\n", m.totalBufferLength.Load())
	fmt.Printf("Total Buffer Size: %d\n", m.totalBufferSize.Load())
	// fmt.Printf("Pre-allocated Buffer Use: %d\n", m.preAllocatedUse.Load())
	fmt.Printf("Average Buffer Growth: %d\n", m.averageGrowth())
	fmt.Printf("\n\n\n")
}

type bufPoolOpt func(pool *bufferPool)

type bufferPool struct {
	bufferSize uint32
	*sync.Pool

	metrics *bufferPoolMetrics
}

const defaultBufferSize = 2 << 12 // 8KB
func newBufferPool(opts ...bufPoolOpt) *bufferPool {
	pool := &bufferPool{bufferSize: defaultBufferSize, metrics: new(bufferPoolMetrics)}

	for _, opt := range opts {
		opt(pool)
	}
	pool.Pool = &sync.Pool{
		New: func() any {
			buf := new(bytes.Buffer)
			buf.Grow(int(pool.bufferSize))
			return buf
		},
	}

	return pool
}

// sharedBufferPool is the shared buffer pool used by all BufferedFileWriters.
// This allows for efficient reuse of buffers across multiple writers.
var sharedBufferPool *bufferPool

func init() { sharedBufferPool = newBufferPool() }

func (bp *bufferPool) get(ctx context.Context) *bytes.Buffer {
	buf, ok := bp.Pool.Get().(*bytes.Buffer)
	if !ok {
		ctx.Logger().Error(fmt.Errorf("buffer pool returned unexpected type"), "using new buffer")
		buf = bytes.NewBuffer(make([]byte, 0, bp.bufferSize))
	}
	bp.metrics.recordBufferRetrival(int64(buf.Cap()), defaultBufferSize)

	return buf
}

func (bp *bufferPool) growBufferWithSize(buf *bytes.Buffer, size int) {
	// Grow the buffer to accommodate the new data.
	bp.metrics.recordGrowth(size)
	buf.Grow(size)
}

func (bp *bufferPool) put(buf *bytes.Buffer) {
	bp.metrics.recordBufferReturn()

	// If the buffer is more than twice the default size, replace it with a new, smaller one.
	// This prevents us from returning very large buffers to the pool.
	const maxAllowedCapacity = 2 * defaultBufferSize
	if buf.Cap() > maxAllowedCapacity {
		// Replace the buffer with a new, smaller one. No need to copy data since we're resetting it.
		buf = bytes.NewBuffer(make([]byte, 0, defaultBufferSize))
	} else {
		// Reset the buffer to clear any existing data.
		buf.Reset()
	}

	bp.Put(buf)
}

// state represents the current mode of BufferedFileWriter.
type state uint8

const (
	// writeOnly indicates the BufferedFileWriter is in write-only mode.
	writeOnly state = iota
	// readOnly indicates the BufferedFileWriter has been closed and is in read-only mode.
	readOnly
)

// BufferedFileWriter manages a buffer for writing data, flushing to a file when a threshold is exceeded.
// It supports either write-only or read-only mode, indicated by its state.
type BufferedFileWriter struct {
	threshold uint64 // Threshold for switching to file writing.
	size      uint64 // Total size of the data written.

	state state // Current state of the writer. (writeOnly or readOnly)

	bufPool  *bufferPool    // Pool for storing buffers for reuse.
	buf      *bytes.Buffer  // Buffer for storing data under the threshold in memory.
	filename string         // Name of the temporary file.
	file     io.WriteCloser // File for storing data over the threshold.
}

// Option is a function that modifies a BufferedFileWriter.
type Option func(*BufferedFileWriter)

// WithThreshold sets the threshold for switching to file writing.
func WithThreshold(threshold uint64) Option {
	return func(w *BufferedFileWriter) { w.threshold = threshold }
}

// New creates a new BufferedFileWriter with the given options.
func New(opts ...Option) *BufferedFileWriter {
	const defaultThreshold = 10 * 1024 * 1024 // 10MB
	w := &BufferedFileWriter{
		threshold: defaultThreshold,
		state:     writeOnly,
		bufPool:   sharedBufferPool,
	}
	for _, opt := range opts {
		opt(w)
	}

	return w
}

// Len returns the number of bytes written to the buffer or file.
func (w *BufferedFileWriter) Len() int { return int(w.size) }

// String returns all the data written to the buffer or file as a string or an empty string if there is an error.
func (w *BufferedFileWriter) String() (string, error) {
	if w.file == nil {
		return w.buf.String(), nil
	}

	// Data is in a file, read from the file.
	file, err := os.Open(w.filename)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var buf bytes.Buffer
	// Read the file contents into the buffer.
	if _, err := io.CopyBuffer(&buf, file, nil); err != nil {
		return "", fmt.Errorf("failed to read file contents: %w", err)
	}

	// Append buffer data, if any, to the end of the file contents.
	if _, err := buf.WriteTo(w.buf); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// Write writes data to the buffer or a file, depending on the size.
func (w *BufferedFileWriter) Write(ctx context.Context, data []byte) (int, error) {
	if w.state != writeOnly {
		return 0, fmt.Errorf("BufferedFileWriter must be in write-only mode to write")
	}

	size := uint64(len(data))

	if w.buf == nil || w.buf.Len() == 0 {
		w.buf = w.bufPool.get(ctx)
	}

	bufferLength := w.buf.Len()

	defer func() {
		w.size += size
		ctx.Logger().V(4).Info(
			"write complete",
			"data_size", size,
			"content_size", bufferLength,
			"total_size", w.size,
		)
	}()

	totalSizeNeeded := uint64(bufferLength) + uint64(len(data))
	if totalSizeNeeded <= w.threshold {
		// If the total size is within the threshold, write to the buffer.
		ctx.Logger().V(4).Info(
			"writing to buffer",
			"data_size", size,
			"content_size", bufferLength,
		)

		growSize := int(totalSizeNeeded - uint64(w.buf.Cap()))
		if growSize > 0 {
			ctx.Logger().V(4).Info(
				"buffer size exceeded, growing buffer",
				"current_size", bufferLength,
				"new_size", totalSizeNeeded,
				"grow_size", growSize,
			)
			w.bufPool.growBufferWithSize(w.buf, growSize)
		}

		return w.buf.Write(data)
	}

	// Switch to file writing if threshold is exceeded.
	// This helps in managing memory efficiently for large content.
	if w.file == nil {
		file, err := os.CreateTemp(os.TempDir(), cleantemp.MkFilename())
		if err != nil {
			return 0, err
		}

		w.filename = file.Name()
		w.file = file

		// Transfer existing data in buffer to the file, then clear the buffer.
		// This ensures all the data is in one place - either entirely in the buffer or the file.
		if bufferLength > 0 {
			ctx.Logger().V(4).Info("writing buffer to file", "content_size", bufferLength)
			if _, err := w.buf.WriteTo(w.file); err != nil {
				return 0, err
			}
			// Reset the buffer to clear any existing data and return it to the pool.
			w.bufPool.put(w.buf)
		}
	}
	ctx.Logger().V(4).Info("writing to file", "data_size", size)

	return w.file.Write(data)
}

// CloseForWriting flushes any remaining data in the buffer to the file, closes the file if created,
// and transitions the BufferedFileWriter to read-only mode.
func (w *BufferedFileWriter) CloseForWriting() error {
	defer func() { w.state = readOnly }()
	if w.file == nil {
		return nil
	}

	if w.buf.Len() > 0 {
		_, err := w.buf.WriteTo(w.file)
		if err != nil {
			return err
		}
	}
	return w.file.Close()
}

// ReadCloser returns an io.ReadCloser to read the written content. It provides a reader
// based on the current storage medium of the data (in-memory buffer or file).
// If the total content size exceeds the predefined threshold, it is stored in a temporary file and a file
// reader is returned. For in-memory data, it returns a custom reader that handles returning
// the buffer to the pool.
// The caller should call Close() on the returned io.Reader when done to ensure files are cleaned up.
// It can only be used when the BufferedFileWriter is in read-only mode.
func (w *BufferedFileWriter) ReadCloser() (io.ReadCloser, error) {
	if w.state != readOnly {
		return nil, fmt.Errorf("BufferedFileWriter must be in read-only mode to read")
	}

	if w.file != nil {
		// Data is in a file, read from the file.
		file, err := os.Open(w.filename)
		if err != nil {
			return nil, err
		}
		return newAutoDeletingFileReader(file), nil
	}

	// Data is in memory.
	return &bufferReadCloser{
		Reader:  bytes.NewReader(w.buf.Bytes()),
		onClose: func() { w.bufPool.put(w.buf) },
	}, nil
}

// autoDeletingFileReader wraps an *os.File and deletes the file on Close.
type autoDeletingFileReader struct{ *os.File }

// newAutoDeletingFileReader creates a new autoDeletingFileReader.
func newAutoDeletingFileReader(file *os.File) *autoDeletingFileReader {
	return &autoDeletingFileReader{File: file}
}

// Close implements the io.Closer interface, deletes the file after closing.
func (r *autoDeletingFileReader) Close() error {
	defer os.Remove(r.Name()) // Delete the file after closing
	return r.File.Close()
}

// bufferReadCloser is a custom implementation of io.ReadCloser. It wraps a bytes.Reader
// for reading data from an in-memory buffer and includes an onClose callback.
// The onClose callback is used to return the buffer to the pool, ensuring buffer re-usability.
type bufferReadCloser struct {
	*bytes.Reader
	onClose func()
}

// Close implements the io.Closer interface. It calls the onClose callback to return the buffer
// to the pool, enabling buffer reuse. This method should be called by the consumers of ReadCloser
// once they have finished reading the data to ensure proper resource management.
func (brc *bufferReadCloser) Close() error {
	if brc.onClose == nil {
		return nil
	}

	brc.onClose() // Return the buffer to the pool
	return nil
}
