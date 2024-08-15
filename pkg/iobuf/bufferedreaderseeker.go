package iobuf

import (
	"errors"
	"io"
	"os"

	"github.com/trufflesecurity/trufflehog/v3/pkg/buffers/buffer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/buffers/pool"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
)

const defaultBufferSize = 1 << 16 // 64KB

var defaultBufferPool *pool.Pool

func init() { defaultBufferPool = pool.NewBufferPool(defaultBufferSize) }

// BufferedReadSeeker provides a buffered reading interface with seeking capabilities.
// It wraps an io.Reader and optionally an io.Seeker, allowing for efficient
// reading and seeking operations, even on non-seekable underlying readers.
//
// For small amounts of data, it uses an in-memory buffer (bytes.Buffer) to store
// read bytes. When the amount of data exceeds a specified threshold, it switches
// to disk-based buffering using a temporary file. This approach balances memory
// usage and performance, allowing efficient handling of both small and large data streams.
//
// The struct manages the transition between in-memory and disk-based buffering
// transparently, providing a seamless reading and seeking experience regardless
// of the underlying data size or the seekability of the original reader.
//
// If the underlying reader is seekable, direct seeking operations are performed
// on it. For non-seekable readers, seeking is emulated using the buffer or
// temporary file.
type BufferedReadSeeker struct {
	reader io.Reader
	seeker io.Seeker // If the reader supports seeking, it's stored here for direct access

	bufPool *pool.Pool     // Pool for storing buffers for reuse.
	buf     *buffer.Buffer // Buffer for storing data under the threshold in memory.

	bytesRead int64 // Total number of bytes read from the underlying reader
	index     int64 // Current position in the virtual stream

	threshold      int64    // Threshold for switching to file buffering
	tempFile       *os.File // Temporary file for disk-based buffering
	tempFileName   string   // Name of the temporary file
	diskBufferSize int64    // Size of data written to disk

	// Fields to provide a quick way to determine the total size of the reader
	// without having to seek.
	totalSize int64 // Total size of the reader
	sizeKnown bool  // Whether the total size of the reader is known
}

// NewBufferedReaderSeeker creates and initializes a BufferedReadSeeker.
// It takes an io.Reader and checks if it supports seeking.
// If the reader supports seeking, it is stored in the seeker field.
func NewBufferedReaderSeeker(r io.Reader) *BufferedReadSeeker {
	const defaultThreshold = 1 << 24 // 16MB threshold for switching to file buffering

	seeker, _ := r.(io.Seeker)

	var buf *buffer.Buffer
	if seeker == nil {
		buf = defaultBufferPool.Get()
	}

	return &BufferedReadSeeker{
		reader:    r,
		seeker:    seeker,
		bufPool:   defaultBufferPool,
		buf:       buf,
		threshold: defaultThreshold,
	}
}

// Read reads len(out) bytes from the reader starting at the current index.
// It handles both seekable and non-seekable underlying readers efficiently.
func (br *BufferedReadSeeker) Read(out []byte) (int, error) {
	if br.seeker != nil {
		// For seekable readers, read directly from the underlying reader.
		n, err := br.reader.Read(out)
		if n > 0 {
			br.bytesRead += int64(n)
		}
		return n, err
	}

	// If we have a temp file and the total size is known, we can read directly from it.
	if br.sizeKnown && br.tempFile != nil {
		if br.index >= br.totalSize {
			return 0, io.EOF
		}
		if _, err := br.tempFile.Seek(br.index, io.SeekStart); err != nil {
			return 0, err
		}
		n, err := br.tempFile.Read(out)
		br.index += int64(n)
		return n, err
	}

	var (
		totalBytesRead int
		err            error
	)

	// If the current read position is within the in-memory buffer.
	if br.index < int64(br.buf.Len()) {
		totalBytesRead = copy(out, br.buf.Bytes()[br.index:])
		br.index += int64(totalBytesRead)
		if totalBytesRead == len(out) {
			return totalBytesRead, nil
		}
		out = out[totalBytesRead:]
	}

	// If we've exceeded the in-memory threshold and have a temp file.
	if br.tempFile != nil && br.index < br.diskBufferSize {
		if _, err := br.tempFile.Seek(br.index-int64(br.buf.Len()), io.SeekStart); err != nil {
			return totalBytesRead, err
		}
		m, err := br.tempFile.Read(out)
		totalBytesRead += m
		br.index += int64(m)
		if err != nil && !errors.Is(err, io.EOF) {
			return totalBytesRead, err
		}
		if totalBytesRead == len(out) {
			return totalBytesRead, nil
		}
		out = out[totalBytesRead:]
	}

	if len(out) == 0 {
		return totalBytesRead, nil
	}

	// If we still need to read more data.
	var raderBytes int
	raderBytes, err = br.reader.Read(out)
	totalBytesRead += raderBytes
	br.index += int64(raderBytes)

	if writeErr := br.writeData(out[:raderBytes]); writeErr != nil {
		return totalBytesRead, writeErr
	}

	if errors.Is(err, io.EOF) {
		br.totalSize = br.bytesRead
		br.sizeKnown = true
	}

	return totalBytesRead, err
}

// Seek sets the offset for the next Read or Write to offset.
// It supports both seekable and non-seekable underlying readers.
func (br *BufferedReadSeeker) Seek(offset int64, whence int) (int64, error) {
	if br.seeker != nil {
		// Use the underlying Seeker if available.
		return br.seeker.Seek(offset, whence)
	}

	// Manual seeking for non-seekable readers.
	newIndex := br.index

	switch whence {
	case io.SeekStart:
		newIndex = offset
	case io.SeekCurrent:
		newIndex += offset
	case io.SeekEnd:
		// If we already know the total size, we can use it directly.
		if !br.sizeKnown {
			if err := br.readToEnd(); err != nil {
				return 0, err
			}
		}
		newIndex = br.totalSize + offset
	default:
		return 0, errors.New("invalid whence value")
	}

	if newIndex < 0 {
		return 0, errors.New("can not seek to before start of reader")
	}

	// For non-seekable readers, we need to ensure we've read up to the new index.
	if br.seeker == nil && newIndex > br.bytesRead {
		if err := br.readUntil(newIndex); err != nil {
			return 0, err
		}
	}

	br.index = newIndex

	// Update bytesRead only if we've moved beyond what we've read so far.
	if br.index > br.bytesRead {
		br.bytesRead = br.index
	}

	return newIndex, nil
}

func (br *BufferedReadSeeker) readToEnd() error {
	buf := br.bufPool.Get()
	defer br.bufPool.Put(buf)

	for {
		n, err := io.CopyN(buf, br.reader, defaultBufferSize)
		if n > 0 {
			// Write the data from the buffer.
			if writeErr := br.writeData(buf.Bytes()[:n]); writeErr != nil {
				return writeErr
			}
		}
		// Reset the buffer for the next iteration.
		buf.Reset()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}

	// If a temporary file exists and the buffer contains data,
	// flush the buffer to the file. This allows future operations
	// to utilize the temporary file exclusively, simplifying
	// management by avoiding separate handling of the buffer and file.
	if br.tempFile != nil && br.buf.Len() > 0 {
		if err := br.flushBufferToDisk(); err != nil {
			return err
		}
	}

	br.totalSize = br.bytesRead
	br.sizeKnown = true

	return nil
}

func (br *BufferedReadSeeker) writeData(data []byte) error {
	_, err := br.buf.Write(data)
	if err != nil {
		return err
	}
	br.bytesRead += int64(len(data))

	// Check if we've reached or exceeded the threshold.
	if br.buf.Len() < int(br.threshold) {
		return nil
	}

	if br.tempFile == nil {
		if err := br.createTempFile(); err != nil {
			return err
		}
	}

	// Flush the buffer to disk.
	return br.flushBufferToDisk()
}

func (br *BufferedReadSeeker) readUntil(index int64) error {
	buf := br.bufPool.Get()
	defer br.bufPool.Put(buf)

	for br.bytesRead < index {
		remaining := index - br.bytesRead
		bufSize := int64(defaultBufferSize)
		if remaining < bufSize {
			bufSize = remaining
		}

		n, err := io.CopyN(buf, br, bufSize)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}

		if n == 0 {
			break
		}

		buf.Reset()
	}

	return nil
}

func (br *BufferedReadSeeker) createTempFile() error {
	tempFile, err := os.CreateTemp(os.TempDir(), cleantemp.MkFilename())
	if err != nil {
		return err
	}
	br.tempFile = tempFile
	br.tempFileName = tempFile.Name()

	return nil
}

func (br *BufferedReadSeeker) flushBufferToDisk() error {
	if _, err := br.buf.WriteTo(br.tempFile); err != nil {
		return err
	}
	br.diskBufferSize = int64(br.buf.Len())

	return nil
}

// ReadAt reads len(out) bytes into out starting at offset off in the underlying input source.
// It uses Seek and Read to implement random access reading.
func (br *BufferedReadSeeker) ReadAt(out []byte, offset int64) (int, error) {
	if br.seeker != nil {
		// Use the underlying Seeker if available.
		_, err := br.Seek(offset, io.SeekStart)
		if err != nil {
			return 0, err
		}
		return br.Read(out)
	}

	// For non-seekable readers, use our buffering logic.
	currentIndex := br.index

	if _, err := br.Seek(offset, io.SeekStart); err != nil {
		return 0, err
	}

	n, err := br.Read(out)
	if err != nil {
		return n, err
	}

	// Seek back to the original position.
	if _, err = br.Seek(currentIndex, io.SeekStart); err != nil {
		return n, err
	}

	return n, err
}

// Close closes the BufferedReadSeeker and releases any resources used.
// It closes the temporary file if one was created and removes it from disk and
// returns the buffer to the pool.
func (br *BufferedReadSeeker) Close() error {
	if br.buf != nil {
		br.bufPool.Put(br.buf)
	}

	if br.tempFile != nil {
		br.tempFile.Close()
		return os.Remove(br.tempFileName)
	}
	return nil
}
