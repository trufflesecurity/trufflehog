package iobuf

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBufferedReaderSeekerRead(t *testing.T) {
	tests := []struct {
		name              string
		reader            io.Reader
		reads             []int
		expectedReads     []int
		expectedBytes     [][]byte
		expectedBytesRead int64
		expectedIndex     int64
		expectedBuffer    []byte
		expectedError     error
	}{
		{
			name:              "read from seekable reader",
			reader:            strings.NewReader("test data"),
			reads:             []int{4},
			expectedReads:     []int{4},
			expectedBytes:     [][]byte{[]byte("test")},
			expectedBytesRead: 4,
			expectedIndex:     4,
		},
		{
			name:              "read from non-seekable reader with buffering",
			reader:            bytes.NewBufferString("test data"),
			reads:             []int{4},
			expectedReads:     []int{4},
			expectedBytes:     [][]byte{[]byte("test")},
			expectedBytesRead: 4,
			expectedIndex:     4,
			expectedBuffer:    []byte("test"),
		},
		{
			name:              "read from non-seekable reader without buffering",
			reader:            bytes.NewBufferString("test data"),
			reads:             []int{4},
			expectedReads:     []int{4},
			expectedBytes:     [][]byte{[]byte("test")},
			expectedBytesRead: 4,
			expectedIndex:     4,
		},
		{
			name:              "read beyond buffer",
			reader:            strings.NewReader("test data"),
			reads:             []int{10},
			expectedReads:     []int{9},
			expectedBytes:     [][]byte{[]byte("test data")},
			expectedBytesRead: 9,
			expectedIndex:     9,
		},
		{
			name:              "read with empty reader",
			reader:            strings.NewReader(""),
			reads:             []int{4},
			expectedReads:     []int{0},
			expectedBytes:     [][]byte{[]byte("")},
			expectedBytesRead: 0,
			expectedIndex:     0,
			expectedError:     io.EOF,
		},
		{
			name:              "read exact buffer size",
			reader:            strings.NewReader("test"),
			reads:             []int{4},
			expectedReads:     []int{4},
			expectedBytes:     [][]byte{[]byte("test")},
			expectedBytesRead: 4,
			expectedIndex:     4,
		},
		{
			name:              "read less than buffer size",
			reader:            strings.NewReader("te"),
			reads:             []int{4},
			expectedReads:     []int{2},
			expectedBytes:     [][]byte{[]byte("te")},
			expectedBytesRead: 2,
			expectedIndex:     2,
		},
		{
			name:              "read more than buffer size without buffering",
			reader:            bytes.NewBufferString("test data"),
			reads:             []int{4},
			expectedReads:     []int{4},
			expectedBytes:     [][]byte{[]byte("test")},
			expectedBytesRead: 4,
			expectedIndex:     4,
		},
		{
			name:              "multiple reads with buffering",
			reader:            bytes.NewBufferString("test data"),
			reads:             []int{4, 5},
			expectedReads:     []int{4, 5},
			expectedBytes:     [][]byte{[]byte("test"), []byte(" data")},
			expectedBytesRead: 9,
			expectedIndex:     9,
			expectedBuffer:    []byte("test data"),
		},
		{
			name:              "multiple reads without buffering",
			reader:            bytes.NewBufferString("test data"),
			reads:             []int{4, 5},
			expectedReads:     []int{4, 5},
			expectedBytes:     [][]byte{[]byte("test"), []byte(" data")},
			expectedBytesRead: 9,
			expectedIndex:     9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			brs := NewBufferedReaderSeeker(tt.reader)

			for i, readSize := range tt.reads {
				buf := make([]byte, readSize)
				n, err := brs.Read(buf)

				assert.Equal(t, tt.expectedReads[i], n, "read %d: unexpected number of bytes read", i+1)
				assert.Equal(t, tt.expectedBytes[i], buf[:n], "read %d: unexpected bytes", i+1)

				if i == len(tt.reads)-1 {
					if tt.expectedError != nil {
						assert.ErrorIs(t, err, tt.expectedError)
					} else {
						assert.NoError(t, err)
					}
				}
			}

			assert.Equal(t, tt.expectedBytesRead, brs.bytesRead)
			if brs.seeker == nil {
				assert.Equal(t, tt.expectedIndex, brs.index)
			}

			if brs.buf != nil && len(tt.expectedBuffer) > 0 {
				assert.Equal(t, tt.expectedBuffer, brs.buf.Bytes())
			} else {
				assert.Nil(t, tt.expectedBuffer)
			}
		})
	}
}

func TestBufferedReaderSeekerSeek(t *testing.T) {
	tests := []struct {
		name         string
		reader       io.Reader
		offset       int64
		whence       int
		expectedPos  int64
		expectedErr  bool
		expectedRead []byte
	}{
		{
			name:         "seek on seekable reader with SeekStart",
			reader:       strings.NewReader("test data"),
			offset:       4,
			whence:       io.SeekStart,
			expectedPos:  4,
			expectedErr:  false,
			expectedRead: []byte(" dat"),
		},
		{
			name:         "seek on seekable reader with SeekCurrent",
			reader:       strings.NewReader("test data"),
			offset:       4,
			whence:       io.SeekCurrent,
			expectedPos:  4,
			expectedErr:  false,
			expectedRead: []byte(" dat"),
		},
		{
			name:         "seek on seekable reader with SeekEnd",
			reader:       strings.NewReader("test data"),
			offset:       -4,
			whence:       io.SeekEnd,
			expectedPos:  5,
			expectedErr:  false,
			expectedRead: []byte("data"),
		},
		{
			name:         "seek on non-seekable reader with SeekStart",
			reader:       bytes.NewBufferString("test data"),
			offset:       4,
			whence:       io.SeekStart,
			expectedPos:  4,
			expectedErr:  false,
			expectedRead: []byte{},
		},
		{
			name:         "seek on non-seekable reader with SeekCurrent",
			reader:       bytes.NewBufferString("test data"),
			offset:       4,
			whence:       io.SeekCurrent,
			expectedPos:  4,
			expectedErr:  false,
			expectedRead: []byte{},
		},
		{
			name:         "seek on non-seekable reader with SeekEnd",
			reader:       bytes.NewBufferString("test data"),
			offset:       -4,
			whence:       io.SeekEnd,
			expectedPos:  5,
			expectedErr:  false,
			expectedRead: []byte{},
		},
		{
			name:         "seek to negative position",
			reader:       strings.NewReader("test data"),
			offset:       -1,
			whence:       io.SeekStart,
			expectedPos:  0,
			expectedErr:  true,
			expectedRead: nil,
		},
		{
			name:         "seek beyond EOF on non-seekable reader",
			reader:       bytes.NewBufferString("test data"),
			offset:       20,
			whence:       io.SeekEnd,
			expectedPos:  29,
			expectedErr:  false,
			expectedRead: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			brs := NewBufferedReaderSeeker(tt.reader)
			pos, err := brs.Seek(tt.offset, tt.whence)
			if tt.expectedErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedPos, pos)
			if len(tt.expectedRead) > 0 {
				buf := make([]byte, len(tt.expectedRead))
				nn, err := brs.Read(buf)
				assert.NoError(t, err)
				assert.Equal(t, len(tt.expectedRead), nn)
				assert.Equal(t, tt.expectedRead, buf[:nn])
			}
		})
	}
}

func TestBufferedReaderSeekerReadAt(t *testing.T) {
	tests := []struct {
		name        string
		reader      io.Reader
		offset      int64
		length      int
		expectedN   int
		expectErr   bool
		expectedOut []byte
	}{
		{
			name:        "read within buffer on seekable reader",
			reader:      strings.NewReader("test data"),
			offset:      5,
			length:      4,
			expectedN:   4,
			expectedOut: []byte("data"),
		},
		{
			name:        "read within buffer on non-seekable reader",
			reader:      bytes.NewBufferString("test data"),
			offset:      5,
			length:      4,
			expectedN:   4,
			expectedOut: []byte("data"),
		},
		{
			name:        "read beyond buffer",
			reader:      strings.NewReader("test data"),
			offset:      9,
			length:      1,
			expectedN:   0,
			expectErr:   true,
			expectedOut: []byte{},
		},
		{
			name:        "read at start",
			reader:      strings.NewReader("test data"),
			offset:      0,
			length:      4,
			expectedN:   4,
			expectedOut: []byte("test"),
		},
		{
			name:        "read with zero length",
			reader:      strings.NewReader("test data"),
			offset:      0,
			length:      0,
			expectedN:   0,
			expectedOut: []byte{},
		},
		{
			name:        "read negative offset",
			reader:      strings.NewReader("test data"),
			offset:      -1,
			length:      4,
			expectedN:   0,
			expectErr:   true,
			expectedOut: []byte{},
		},
		{
			name:        "read beyond end on non-seekable reader",
			reader:      bytes.NewBufferString("test data"),
			offset:      20,
			length:      4,
			expectedN:   0,
			expectErr:   true,
			expectedOut: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			brs := NewBufferedReaderSeeker(tt.reader)

			out := make([]byte, tt.length)
			n, err := brs.ReadAt(out, tt.offset)
			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedN, n)
			assert.Equal(t, tt.expectedOut, out[:n])
		})
	}
}

// TestBufferedReadSeekerSize tests the Size method of BufferedReadSeeker.
func TestBufferedReadSeekerSize(t *testing.T) {
	tests := []struct {
		name           string
		reader         io.Reader
		setup          func(*BufferedReadSeeker)
		expectedSize   int64
		expectError    bool
		verifyPosition func(*BufferedReadSeeker, int64)
	}{
		{
			name:         "size of seekable reader",
			reader:       strings.NewReader("Hello, World!"),
			expectedSize: 13,
		},
		{
			name:         "size of non-seekable reader",
			reader:       bytes.NewBufferString("Hello, World!"),
			expectedSize: 13,
		},
		{
			name:         "size of empty seekable reader",
			reader:       strings.NewReader(""),
			expectedSize: 0,
		},
		{
			name:         "size of empty non-seekable reader",
			reader:       bytes.NewBufferString(""),
			expectedSize: 0,
		},
		{
			name:   "size of non-seekable reader after partial read",
			reader: bytes.NewBufferString("Partial read data"),
			setup: func(brs *BufferedReadSeeker) {
				// Read first 7 bytes ("Partial").
				buf := make([]byte, 7)
				_, _ = brs.Read(buf)
			},
			expectedSize: 17, // "Partial read data" is 16 bytes
			expectError:  false,
			verifyPosition: func(brs *BufferedReadSeeker, expectedSize int64) {
				// After Size is called, the read position should remain at 7
				currentPos, err := brs.Seek(0, io.SeekCurrent)
				assert.NoError(t, err)
				assert.Equal(t, int64(7), currentPos)
			},
		},
		{
			name:         "repeated Size calls",
			reader:       strings.NewReader("Repeated Size Calls Test"),
			expectedSize: 24,
			expectError:  false,
			setup: func(brs *BufferedReadSeeker) {
				// Call Size multiple times.
				size1, err1 := brs.Size()
				assert.NoError(t, err1)
				assert.Equal(t, int64(24), size1)

				size2, err2 := brs.Size()
				assert.NoError(t, err2)
				assert.Equal(t, int64(24), size2)
			},
		},
		{
			name: "size with error during reading",
			reader: &errorReader{
				data:       "Data before error",
				errorAfter: 5, // Return error after reading 5 bytes
			},
			expectedSize: 0,
			expectError:  true,
		},
		{
			name:         "size with limited reader simulating EOF",
			reader:       io.LimitReader(strings.NewReader("Limited data"), 7),
			expectedSize: 7,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			brs := NewBufferedReaderSeeker(tt.reader)

			if tt.setup != nil {
				tt.setup(brs)
			}

			size, err := brs.Size()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedSize, size)
			}

			if tt.verifyPosition != nil {
				tt.verifyPosition(brs, tt.expectedSize)
			}
		})
	}
}

// errorReader is an io.Reader that returns an error after reading a specified number of bytes.
// It's used to simulate non-EOF errors during read operations.
type errorReader struct {
	data       string
	errorAfter int // Number of bytes to read before returning an error
	readBytes  int
}

func (er *errorReader) Read(p []byte) (int, error) {
	if er.readBytes >= er.errorAfter {
		return 0, errors.New("simulated read error")
	}
	remaining := er.errorAfter - er.readBytes
	toRead := len(p)
	if toRead > remaining {
		toRead = remaining
	}
	copy(p, er.data[er.readBytes:er.readBytes+toRead])
	er.readBytes += toRead
	return toRead, nil
}
