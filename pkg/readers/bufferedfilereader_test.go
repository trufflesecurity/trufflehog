package readers

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBufferedFileReader(t *testing.T) {
	t.Parallel()

	data := []byte("Hello, World!")

	bufferReadSeekCloser, err := NewBufferedFileReader(bytes.NewReader(data))
	assert.NoError(t, err)

	// Test Read.
	buffer := make([]byte, len(data))
	n, err := bufferReadSeekCloser.Read(buffer)
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buffer)

	// Test Seek.
	offset := 7
	seekPos, err := bufferReadSeekCloser.Seek(int64(offset), io.SeekStart)
	assert.NoError(t, err)
	assert.Equal(t, int64(offset), seekPos)

	// Test ReadAt.
	buffer = make([]byte, len(data)-offset)
	n, err = bufferReadSeekCloser.ReadAt(buffer, int64(offset))
	assert.NoError(t, err)
	assert.Equal(t, len(data)-offset, n)
	assert.Equal(t, data[offset:], buffer)

	// Test Close.
	err = bufferReadSeekCloser.Close()
	assert.NoError(t, err)
}

func TestBufferedFileReaderClose(t *testing.T) {
	t.Parallel()

	data := []byte("Hello, World!")

	bufferReadSeekCloser, err := NewBufferedFileReader(bytes.NewReader(data))
	assert.NoError(t, err)

	err = bufferReadSeekCloser.Close()
	assert.NoError(t, err)

	// Read should NOT return any data after closing the reader.
	buffer := make([]byte, len(data))
	n, err := bufferReadSeekCloser.Read(buffer)
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, 0, n)
}

func TestBufferedFileReaderReadFromFile(t *testing.T) {
	t.Parallel()

	// Create a large byte slice to simulate data exceeding the threshold.
	largeData := make([]byte, 1024*1024) // 1 MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	bufferReadSeekCloser, err := NewBufferedFileReader(bytes.NewReader(largeData))
	assert.NoError(t, err)
	defer bufferReadSeekCloser.Close()

	// Test Read.
	buffer := make([]byte, len(largeData))
	n, err := bufferReadSeekCloser.Read(buffer)
	assert.NoError(t, err)
	assert.Equal(t, len(largeData), n)
	assert.Equal(t, largeData, buffer)

	// Test Seek.
	offset := 512 * 1024 // 512 KB
	seekPos, err := bufferReadSeekCloser.Seek(int64(offset), io.SeekStart)
	assert.NoError(t, err)
	assert.Equal(t, int64(offset), seekPos)

	// Test ReadAt.
	buffer = make([]byte, len(largeData)-offset)
	n, err = bufferReadSeekCloser.ReadAt(buffer, int64(offset))
	assert.NoError(t, err)
	assert.Equal(t, len(largeData)-offset, n)
	assert.Equal(t, largeData[offset:], buffer)

	// Test Close.
	err = bufferReadSeekCloser.Close()
	assert.NoError(t, err)
}
