// Package bufferedfilewriter provides a writer that buffers data in memory until a threshold is exceeded at
// which point it switches to writing to a temporary file.
package bufferedfilewriter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/buffers/buffer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/buffers/pool"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
)

type bufferedFileWriterMetrics struct{}

func (bufferedFileWriterMetrics) recordDataProcessed(size uint64, dur time.Duration) {
	totalWriteSize.Add(float64(size))
	totalWriteDuration.Add(float64(dur.Microseconds()))
}

func (bufferedFileWriterMetrics) recordDiskWrite(size int64) {
	diskWriteCount.Inc()
	fileSizeHistogram.Observe(float64(size))
}

type PoolSize int

const (
	Default PoolSize = iota
	Large
)

const (
	defaultBufferSize = 1 << 12 // 4KB
	largeBufferSize   = 1 << 16 // 64KB
)

func init() {
	defaultBufferPool = pool.NewBufferPool(defaultBufferSize)
	largeBufferPool = pool.NewBufferPool(largeBufferSize)
}

// Different buffer pools for different buffer sizes.
// This allows for more efficient memory management based on the size of the data being written.
var (
	defaultBufferPool *pool.Pool
	largeBufferPool   *pool.Pool
)

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

	bufPool  *pool.Pool     // Pool for storing buffers for reuse.
	buf      *buffer.Buffer // Buffer for storing data under the threshold in memory.
	filename string         // Name of the temporary file.
	file     *os.File       // File for storing data over the threshold.

	state state // Current state of the writer. (writeOnly or readOnly)

	metrics bufferedFileWriterMetrics
}

// Option is a function that modifies a BufferedFileWriter.
type Option func(*BufferedFileWriter)

// WithThreshold sets the threshold for switching to file writing.
func WithThreshold(threshold uint64) Option {
	return func(w *BufferedFileWriter) { w.threshold = threshold }
}

// WithBufferSize sets the buffer size for the BufferedFileWriter.
func WithBufferSize(size PoolSize) Option {
	return func(w *BufferedFileWriter) {
		switch size {
		case Default:
			w.bufPool = defaultBufferPool
		case Large:
			w.bufPool = largeBufferPool
		default:
			w.bufPool = defaultBufferPool
		}
	}
}

const defaultThreshold = 10 * 1024 * 1024 // 10MB
// New creates a new BufferedFileWriter with the given options.
func New(opts ...Option) *BufferedFileWriter {
	w := &BufferedFileWriter{
		threshold: defaultThreshold,
		state:     writeOnly,
	}

	for _, opt := range opts {
		opt(w)
	}

	if w.bufPool == nil {
		w.bufPool = defaultBufferPool
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
	if _, err := w.buf.WriteTo(&buf); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// Write writes data to the buffer or a file, depending on the size.
func (w *BufferedFileWriter) Write(data []byte) (int, error) {
	if w.state != writeOnly {
		return 0, fmt.Errorf("BufferedFileWriter must be in write-only mode to write")
	}

	if w.buf == nil {
		w.buf = w.bufPool.Get()
		if w.buf == nil {
			w.buf = buffer.NewBuffer()
		}
	}

	size := uint64(len(data))
	bufferLength := w.buf.Len()
	start := time.Now()
	defer func(start time.Time) {
		w.metrics.recordDataProcessed(size, time.Since(start))
		w.size += size
	}(start)

	totalSizeNeeded := uint64(bufferLength) + size
	if totalSizeNeeded <= w.threshold {
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
			if _, err := w.buf.WriteTo(w.file); err != nil {
				if err := os.RemoveAll(w.filename); err != nil {
					return 0, fmt.Errorf("failed to remove file: %w", err)
				}
				return 0, err
			}
		}
	}

	// Write any remaining data in the buffer to the file before writing new data.
	if w.buf.Len() > 0 {
		if _, err := w.buf.WriteTo(w.file); err != nil {
			return 0, fmt.Errorf("error flushing buffer to file: %w", err)
		}
	}

	n, err := w.file.Write(data)
	if err != nil {
		return n, err
	}
	w.metrics.recordDiskWrite(int64(n))

	return n, nil
}

// ReadFrom reads data from the provided reader and writes it to the buffer or file, depending on the size.
// This method satisfies the io.ReaderFrom interface, allowing it to be used with standard library functions
// like io.Copy and io.CopyBuffer.
//
// By implementing this method, BufferedFileWriter can leverage optimized data transfer mechanisms provided
// by the standard library. For example, when using io.Copy with a BufferedFileWriter, the copy operation
// will be delegated to the ReadFrom method, avoiding the potentially non-optimized default approach.
//
// This is particularly useful when creating a new BufferedFileWriter from an io.Reader using the NewFromReader
// function. By leveraging the ReadFrom method, data can be efficiently transferred from the reader to
// the BufferedFileWriter.
func (w *BufferedFileWriter) ReadFrom(reader io.Reader) (int64, error) {
	if w.state != writeOnly {
		return 0, fmt.Errorf("BufferedFileWriter must be in write-only mode to write")
	}

	var totalBytesRead int64
	const bufferSize = 1 << 16 // 64KB
	buf := make([]byte, bufferSize)

	for {
		n, err := reader.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			return totalBytesRead, err
		}
		if n > 0 {
			written, err := w.Write(buf[:n])
			if err != nil {
				return totalBytesRead, err
			}
			totalBytesRead += int64(written)
		}

		if errors.Is(err, io.EOF) {
			break
		}
	}

	return totalBytesRead, nil
}

// CloseForWriting flushes any remaining data in the buffer to the file, closes the file if created,
// and transitions the BufferedFileWriter to read-only mode.
func (w *BufferedFileWriter) CloseForWriting() error {
	defer func() { w.state = readOnly }()
	if w.file == nil {
		return nil
	}

	// Return the buffer to the pool since the contents have been written to the file and
	// the writer is transitioning to read-only mode.
	defer w.bufPool.Put(w.buf)

	if w.buf.Len() > 0 {
		if _, err := w.buf.WriteTo(w.file); err != nil {
			return err
		}
	}
	return w.file.Close()
}

// ReadCloser returns an io.ReadCloser to read the written content.
// If the content is stored in a file, it opens the file and returns a file reader.
// If the content is stored in memory, it returns a custom reader that handles returning the buffer to the pool.
// The caller should call Close() on the returned io.Reader when done to ensure resources are properly released.
// This method can only be used when the BufferedFileWriter is in read-only mode.
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

	if w.buf == nil {
		return nil, nil
	}

	// Data is in memory.
	return buffer.ReadCloser(w.buf.Bytes(), func() { w.bufPool.Put(w.buf) }), nil
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
