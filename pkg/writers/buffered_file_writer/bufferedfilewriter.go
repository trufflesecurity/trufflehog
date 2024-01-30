// Package bufferedfilewriter provides a writer that buffers data in memory until a threshold is exceeded at
// which point it switches to writing to a temporary file.
package bufferedfilewriter

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// bufferPool is used to store buffers for reuse.
var bufferPool = sync.Pool{
	// TODO: Consider growing the buffer before returning it if we can find an optimal size.
	// Ideally the size would cover the majority of cases without being too large.
	// This would avoid the need to grow the buffer when writing to it, reducing allocations.
	New: func() any { return new(bytes.Buffer) },
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

	buf      bytes.Buffer   // Buffer for storing data under the threshold in memory.
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
	w := &BufferedFileWriter{threshold: defaultThreshold, state: writeOnly}
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

	// Create a buffer large enough to hold file data and additional buffer data, if any.
	fileSize := w.size
	buf := bytes.NewBuffer(make([]byte, 0, fileSize))

	// Read the file contents into the buffer.
	if _, err := io.Copy(buf, file); err != nil {
		return "", fmt.Errorf("failed to read file contents: %w", err)
	}

	// Append buffer data, if any, to the end of the file contents.
	buf.Write(w.buf.Bytes())

	return buf.String(), nil
}

// Write writes data to the buffer or a file, depending on the size.
func (w *BufferedFileWriter) Write(ctx context.Context, data []byte) (int, error) {
	if w.state != writeOnly {
		return 0, fmt.Errorf("BufferedFileWriter must be in write-only mode to write")
	}

	size := uint64(len(data))
	defer func() {
		w.size += size
		ctx.Logger().V(4).Info(
			"write complete",
			"data_size", size,
			"content_size", w.buf.Len(),
			"total_size", w.size,
		)
	}()

	if w.buf.Len() == 0 {
		bufPtr, ok := bufferPool.Get().(*bytes.Buffer)
		if !ok {
			ctx.Logger().Error(fmt.Errorf("buffer pool returned unexpected type"), "using new buffer")
			bufPtr = new(bytes.Buffer)
		}
		bufPtr.Reset() // Reset the buffer to clear any existing data
		w.buf = *bufPtr
	}

	if uint64(w.buf.Len())+size <= w.threshold {
		// If the total size is within the threshold, write to the buffer.
		ctx.Logger().V(4).Info(
			"writing to buffer",
			"data_size", size,
			"content_size", w.buf.Len(),
		)
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
		if w.buf.Len() > 0 {
			ctx.Logger().V(4).Info("writing buffer to file", "content_size", w.buf.Len())
			if _, err := w.file.Write(w.buf.Bytes()); err != nil {
				return 0, err
			}
			// Reset the buffer to clear any existing data and return it to the pool.
			w.buf.Reset()
			bufferPool.Put(&w.buf)
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
		_, err := w.file.Write(w.buf.Bytes())
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
		onClose: func() { bufferPool.Put(&w.buf) },
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
