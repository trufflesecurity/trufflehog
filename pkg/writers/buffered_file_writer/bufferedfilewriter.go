package bufferedfilewriter

import (
	"bytes"
	"io"
	"os"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// BufferedFileWriter manages a buffer for writing data, flushing to a file when a threshold is exceeded.
type BufferedFileWriter struct {
	threshold uint64
	buf       bytes.Buffer
	file      *os.File
}

// Option is a function that modifies a BufferedFileWriter.
type Option func(*BufferedFileWriter)

// WithThreshold sets the threshold for switching to file writing.
func WithThreshold(threshold uint64) Option {
	return func(w *BufferedFileWriter) { w.threshold = threshold }
}

// New creates a new BufferedFileWriter with the given options.
func New(opts ...Option) *BufferedFileWriter {
	const defaultThreshold = 20 * 1024 * 1024 // 20MB
	w := &BufferedFileWriter{threshold: defaultThreshold}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Len returns the number of bytes in the buffer.
func (w *BufferedFileWriter) Len() int { return w.buf.Len() }

// String returns the contents of the buffer as a string.
func (w *BufferedFileWriter) String() string { return w.buf.String() }

// Write writes data to the buffer or a file, depending on the size.
func (w *BufferedFileWriter) Write(ctx context.Context, p []byte) (int, error) {
	if uint64(w.buf.Len()+len(p)) <= w.threshold {
		// If the total size is within the threshold, write to the buffer.
		ctx.Logger().V(4).Info(
			"writing to buffer",
			"data_size", len(p),
			"content_size", w.buf.Len(),
		)
		return w.buf.Write(p)
	}

	// Switch to file writing if threshold is exceeded.
	// This helps in managing memory efficiently for large diffs.
	if w.file == nil {
		var err error
		w.file, err = os.CreateTemp(os.TempDir(), cleantemp.MkFilename())
		if err != nil {
			return 0, err
		}

		// Transfer existing data in buffer to the file, then clear the buffer.
		// This ensures all the diff data is in one place - either entirely in the buffer or the file.
		if w.buf.Len() > 0 {
			ctx.Logger().V(4).Info("writing buffer to file", "content_size", w.buf.Len())
			if _, err := w.file.Write(w.buf.Bytes()); err != nil {
				return 0, err
			}
			// Replace the buffer with a new one to free up memory.
			w.buf = bytes.Buffer{}
		}
	}
	ctx.Logger().V(4).Info("writing to file", "data_size", len(p))

	return w.file.Write(p)
}

// Close flushes any remaining data in the buffer to the file and closes the file if it was created.
func (w *BufferedFileWriter) Close() error {
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

// ReadCloser returns an io.ReadCloser to read the written content. If the total content size exceeds the
// predefined threshold, it is stored in a temporary file and a file reader is returned.
// For content under the threshold, it is kept in memory and a bytes reader on the buffer is returned.
// The caller should call Close() on the returned io.Reader when done to ensure files are cleaned up.
func (w *BufferedFileWriter) ReadCloser() (io.ReadCloser, error) {
	if w.file != nil {
		// Data is in a file, read from the file.
		file, err := os.Open(w.file.Name())
		if err != nil {
			return nil, err
		}
		return newAutoDeletingFileReader(file), nil
	}
	// Data is in memory.
	return io.NopCloser(bytes.NewReader(w.buf.Bytes())), nil
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
