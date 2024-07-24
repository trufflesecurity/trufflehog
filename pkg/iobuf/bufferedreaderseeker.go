package iobuf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
)

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

	buffer *bytes.Buffer // Internal buffer to store read bytes for non-seekable readers

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
	const (
		defaultThreshold   = 1 << 24 // 16MB threshold for switching to file buffering
		mimeTypeBufferSize = 3072    // Approx buffer size for MIME type detection
	)
	seeker, _ := r.(io.Seeker)

	var buffer *bytes.Buffer
	if seeker == nil {
		buffer = bytes.NewBuffer(make([]byte, 0, mimeTypeBufferSize))
	}

	return &BufferedReadSeeker{
		reader:    r,
		seeker:    seeker,
		buffer:    buffer,
		bytesRead: 0,
		index:     0,
		threshold: defaultThreshold,
	}
}

// Read reads len(out) bytes from the reader starting at the current index.
// It handles both seekable and non-seekable underlying readers efficiently.
func (br *BufferedReadSeeker) Read(out []byte) (int, error) {
	if br.seeker != nil {
		// For seekable readers, read directly from the underlying reader.
		n, err := br.reader.Read(out)
		br.index += int64(n)
		br.bytesRead = max(br.bytesRead, br.index)
		return n, err
	}

	var (
		n   int
		err error
	)

	// If the current read position is within the in-memory buffer.
	if br.index < int64(br.buffer.Len()) {
		n = copy(out, br.buffer.Bytes()[br.index:])
		br.index += int64(n)
		if n == len(out) {
			return n, nil
		}
		out = out[n:]
	}

	// If we've exceeded the in-memory threshold and have a temp file.
	if br.tempFile != nil && br.index < br.diskBufferSize {
		if _, err := br.tempFile.Seek(br.index-int64(br.buffer.Len()), io.SeekStart); err != nil {
			return n, err
		}
		m, err := br.tempFile.Read(out)
		n += m
		br.index += int64(m)
		if err != nil && !errors.Is(err, io.EOF) {
			return n, err
		}
		if n == len(out) {
			return n, nil
		}
		out = out[n:]
	}

	if len(out) == 0 {
		return n, nil
	}

	// If we still need to read more data.
	var m int
	m, err = br.reader.Read(out)
	n += m
	br.index += int64(m)
	br.bytesRead = max(br.bytesRead, br.index)

	if writeErr := br.writeData(out[:m]); writeErr != nil {
		return n, writeErr
	}

	if errors.Is(err, io.EOF) {
		br.totalSize = br.bytesRead
		br.sizeKnown = true
	}

	return n, err
}

// Seek sets the offset for the next Read or Write to offset.
// It supports both seekable and non-seekable underlying readers.
func (br *BufferedReadSeeker) Seek(offset int64, whence int) (int64, error) {
	if br.seeker != nil {
		// Use the underlying Seeker if available.
		newIndex, err := br.seeker.Seek(offset, whence)
		if err != nil {
			return 0, fmt.Errorf("error seeking in reader: %w", err)
		}
		if newIndex > br.bytesRead {
			br.bytesRead = newIndex
		}
		return newIndex, nil
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
	return newIndex, nil
}

const bufferSize = 64 * 1024 // 64KB chunk size for reading
func (br *BufferedReadSeeker) readToEnd() error {
	buffer := make([]byte, bufferSize)
	for {
		n, err := br.reader.Read(buffer)
		if n > 0 {
			if err := br.writeData(buffer[:n]); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	br.totalSize = br.bytesRead
	br.sizeKnown = true

	return nil
}

func (br *BufferedReadSeeker) writeData(data []byte) error {
	br.buffer.Write(data)
	br.bytesRead += int64(len(data))

	// Check if we've reached or exceeded the threshold.
	if br.buffer.Len() < int(br.threshold) {
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
	for br.bytesRead < index {
		remaining := index - br.bytesRead
		bufSize := int64(bufferSize)
		if remaining < bufSize {
			bufSize = remaining
		}

		buf := make([]byte, bufSize)
		n, err := br.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}

		if n == 0 {
			break // We've reached the end of the reader
		}
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
	if _, err := br.buffer.WriteTo(br.tempFile); err != nil {
		return err
	}
	br.diskBufferSize = int64(br.buffer.Len())

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

func (br *BufferedReadSeeker) Close() error {
	if br.tempFile != nil {
		br.tempFile.Close()
		return os.Remove(br.tempFileName)
	}
	return nil
}
