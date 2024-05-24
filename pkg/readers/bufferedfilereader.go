package readers

import (
	"fmt"
	"io"

	bufferedfilewriter "github.com/trufflesecurity/trufflehog/v3/pkg/writers/buffered_file_writer"
)

// Compile time check to ensure that BufferedFileReader implements io.ReaderAt.
var _ io.ReaderAt = (*BufferedFileReader)(nil)

// BufferedFileReader provides random access read, seek, and close capabilities on top of the BufferedFileWriter.
// It combines the functionality of BufferedFileWriter for buffered writing, io.ReadSeekCloser for
// random access reading and seeking.
type BufferedFileReader struct {
	bufWriter *bufferedfilewriter.BufferedFileWriter
	reader    io.ReadSeekCloser
}

// NewBufferedFileReader initializes a BufferedFileReader from an io.Reader by using
// the BufferedFileWriter's functionality to read and store data, then setting up a io.ReadSeekCloser
// for random access reading and seeking.
// Close should be called when the BufferedFileReader is no longer needed.
// It returns the initialized BufferedFileReader and any error encountered during the process.
func NewBufferedFileReader(r io.Reader) (*BufferedFileReader, error) {
	writer, err := bufferedfilewriter.NewFromReader(r)
	if err != nil {
		return nil, fmt.Errorf("error creating BufferedFileReader: %w", err)
	}

	// Ensure that the BufferedFileWriter is in read-only mode.
	if err := writer.CloseForWriting(); err != nil {
		return nil, err
	}

	rdr, err := writer.ReadSeekCloser()
	if err != nil {
		return nil, err
	}

	return &BufferedFileReader{writer, rdr}, nil
}

// Close the BufferedFileReader.
// It should be called when the BufferedFileReader is no longer needed.
// Note that closing the BufferedFileReader does not affect the underlying bytes.Reader,
// which can still be used for reading, seeking, and reading at specific positions.
// Close is a no-op for the bytes.Reader.
func (b *BufferedFileReader) Close() error { return b.reader.Close() }

// Read reads up to len(p) bytes into p from the underlying reader.
// It returns the number of bytes read and any error encountered.
// If the reader reaches the end of the available data, Read returns 0, io.EOF.
// It implements the io.Reader interface.
func (b *BufferedFileReader) Read(p []byte) (int, error) { return b.reader.Read(p) }

// Seek sets the offset for the next Read operation on the underlying reader.
// The offset is interpreted according to the whence parameter:
//   - io.SeekStart means relative to the start of the file
//   - io.SeekCurrent means relative to the current offset
//   - io.SeekEnd means relative to the end of the file
//
// Seek returns the new offset and any error encountered.
// It implements the io.Seeker interface.
func (b *BufferedFileReader) Seek(offset int64, whence int) (int64, error) {
	return b.reader.Seek(offset, whence)
}

// ReadAt reads len(p) bytes from the underlying io.ReadSeekCloser starting at byte offset off.
// It returns the number of bytes read and any error encountered.
// If the io.ReadSeekCloser reaches the end of the available data before len(p) bytes are read,
// ReadAt returns the number of bytes read and io.EOF.
// It implements the io.ReaderAt interface.
func (b *BufferedFileReader) ReadAt(p []byte, off int64) (n int, err error) {
	_, err = b.reader.Seek(off, io.SeekStart)
	if err != nil {
		return 0, err
	}
	return b.reader.Read(p)
}

// Size returns the total size of the data stored in the BufferedFileReader.
func (b *BufferedFileReader) Size() int { return b.bufWriter.Len() }
