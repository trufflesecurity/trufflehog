package iobuf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// BufferedReadSeeker provides a buffered reading interface with seeking capabilities.
// It wraps an io.Reader and optionally an io.Seeker, allowing for efficient
// reading and seeking operations, even on non-seekable underlying readers.
type BufferedReadSeeker struct {
	reader io.Reader
	seeker io.Seeker // If the reader supports seeking, it's stored here for direct access

	buffer *bytes.Buffer // Internal buffer to store read bytes for non-seekable readers

	bytesRead int64 // Total number of bytes read from the underlying reader
	index     int64 // Current position in the virtual stream

	// Flag to control buffering. This flag is used to indicate whether buffering is active.
	// Buffering is enabled during initial reads (e.g., for MIME type detection and format identification).
	// Once these operations are done, buffering should be disabled to prevent further writes to the buffer
	// and to optimize subsequent reads directly from the underlying reader. This helps avoid excessive
	// memory usage while still providing the necessary functionality for initial detection operations.
	activeBuffering bool
}

// NewBufferedReaderSeeker creates and initializes a BufferedReadSeeker.
// It takes an io.Reader and checks if it supports seeking.
// If the reader supports seeking, it is stored in the seeker field.
func NewBufferedReaderSeeker(r io.Reader) *BufferedReadSeeker {
	var (
		seeker          io.Seeker
		buffer          *bytes.Buffer
		activeBuffering = true
	)
	if s, ok := r.(io.Seeker); ok {
		seeker = s
		activeBuffering = false
	}

	const mimeTypeBufferSize = 3072 // Approx buffer size for MIME type detection

	if seeker == nil {
		buffer = bytes.NewBuffer(make([]byte, 0, mimeTypeBufferSize))
	}

	return &BufferedReadSeeker{
		reader:          r,
		seeker:          seeker,
		buffer:          buffer,
		bytesRead:       0,
		index:           0,
		activeBuffering: activeBuffering,
	}
}

// Read reads len(out) bytes from the reader starting at the current index.
// It handles both seekable and non-seekable underlying readers efficiently.
func (br *BufferedReadSeeker) Read(out []byte) (int, error) {
	// For seekable readers, read directly from the underlying reader.
	if br.seeker != nil {
		n, err := br.reader.Read(out)
		br.index += int64(n)
		br.bytesRead = max(br.bytesRead, br.index)
		return n, err
	}

	// For non-seekable readers, use buffered reading.
	outLen := int64(len(out))
	if outLen == 0 {
		return 0, nil
	}

	// If the current read position (br.index) is within the buffer's valid data range,
	// read from the buffer. This ensures previously read data (e.g., for mime type detection)
	// is included in subsequent reads, providing a consistent view of the reader's content.
	if br.index < int64(br.buffer.Len()) {
		n := copy(out, br.buffer.Bytes()[br.index:])
		br.index += int64(n)
		return n, nil
	}

	if !br.activeBuffering {
		// If buffering is not active, read directly from the underlying reader.
		n, err := br.reader.Read(out)
		br.index += int64(n)
		br.bytesRead = max(br.bytesRead, br.index)
		return n, err
	}

	// Ensure there are enough bytes in the buffer to read from.
	if outLen+br.index > int64(br.buffer.Len()) {
		bytesToRead := int(outLen + br.index - int64(br.buffer.Len()))
		readerBytes := make([]byte, bytesToRead)
		n, err := br.reader.Read(readerBytes)
		br.buffer.Write(readerBytes[:n])
		br.bytesRead += int64(n)

		if err != nil {
			return n, err
		}
	}

	// Ensure the read does not exceed the buffer length.
	endIndex := br.index + outLen
	bufLen := int64(br.buffer.Len())
	if endIndex > bufLen {
		endIndex = bufLen
	}

	if br.index >= bufLen {
		return 0, io.EOF
	}

	n := copy(out, br.buffer.Bytes()[br.index:endIndex])
	br.index += int64(n)
	return n, nil
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

	const bufferSize = 64 * 1024 // 64KB chunk size for reading

	switch whence {
	case io.SeekStart:
		newIndex = offset
	case io.SeekCurrent:
		newIndex += offset
	case io.SeekEnd:
		// Read the entire reader to determine its length
		buffer := make([]byte, bufferSize)
		for {
			n, err := br.reader.Read(buffer)
			if n > 0 {
				if br.activeBuffering {
					br.buffer.Write(buffer[:n])
				}
				br.bytesRead += int64(n)
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return 0, err
			}
		}
		newIndex = min(br.bytesRead+offset, br.bytesRead)
	default:
		return 0, errors.New("invalid whence value")
	}

	if newIndex < 0 {
		return 0, errors.New("can not seek to before start of reader")
	}

	br.index = newIndex

	return newIndex, nil
}

// ReadAt reads len(out) bytes into out starting at offset off in the underlying input source.
// It uses Seek and Read to implement random access reading.
func (br *BufferedReadSeeker) ReadAt(out []byte, offset int64) (int, error) {
	startIndex, err := br.Seek(offset, io.SeekStart)
	if err != nil {
		return 0, err
	}

	if startIndex != offset {
		return 0, io.EOF
	}

	return br.Read(out)
}

// DisableBuffering stops the buffering process.
// This is useful after initial reads (e.g., for MIME type detection and format identification)
// to prevent further writes to the buffer, optimizing subsequent reads.
func (br *BufferedReadSeeker) DisableBuffering() { br.activeBuffering = false }
