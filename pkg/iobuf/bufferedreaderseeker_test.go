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

// TestBufferedReaderSeekerRead_SpansBufferAndTempFile is a regression test
// for issue #4569: when a single Read() runs both the in-memory buffer
// branch and the on-disk temp file branch, the slice arithmetic must use
// the per-branch read count (not the cumulative total) when re-slicing
// `out`. Previously this panicked with `slice bounds out of range [N:M]`
// where N was the cumulative count and M the remaining length.
//
// The bug requires a state where buf.Len() > 0 AND diskBufferSize > 0 AND
// the read position falls inside both ranges. Reaching that state needs
// a flush followed by additional buffered writes that do not flush again,
// then a Seek back so the next Read enters branch 1 with a small `out`.
func TestBufferedReaderSeekerRead_SpansBufferAndTempFile(t *testing.T) {
	t.Parallel()

	type primingStep struct {
		// size is the number of bytes to Read from brs in this step.
		size int
	}

	tests := []struct {
		name string
		// threshold controls when writeData() flushes buf to tempFile.
		threshold int64
		// payloadSize must be larger than every read so reader.Read never
		// hits EOF (sizeKnown stays false, keeping the buffered/disk path
		// active instead of the sizeKnown fast path).
		payloadSize int
		// priming reads run before the seek-back; each one drives writeData()
		// and shapes the buf / tempFile state.
		priming []primingStep
		// seekTo is the virtual position to seek to before the final Read.
		seekTo int64
		// finalReadSize is the size of the read that must span both branches.
		// Picked so that the cumulative-count bug would slice past the
		// already-shortened tail of `out`.
		finalReadSize int
	}{
		{
			// Original #4569 shape: one flush, then a small follow-up read
			// leaves a few bytes in buf. Seek to 0 and request 20 bytes;
			// branch 1 returns 8, branch 2 returns the remaining 12, and
			// the pre-fix code re-slices with totalBytesRead=20 against a
			// 12-byte tail, panicking with "slice bounds out of range".
			name:          "small-read across boundary",
			threshold:     32,
			payloadSize:   1 << 12,
			priming:       []primingStep{{size: 32}, {size: 8}},
			seekTo:        0,
			finalReadSize: 20,
		},
		{
			// Adjacent edge case: branch 2 fully fills the post-branch-1
			// tail of `out`. Pre-fix this also panicked because the
			// `if totalBytesRead == len(out)` guard compared the cumulative
			// count to the shortened slice length.
			name:          "branch 2 exactly fills tail",
			threshold:     32,
			payloadSize:   1 << 12,
			priming:       []primingStep{{size: 32}, {size: 16}},
			seekTo:        0,
			finalReadSize: 32, // 16 from buf + 16 from tempFile
		},
		{
			// Branch 1 alone satisfies the read; branch 2 must not run.
			// Verifies the early-return short-circuit still works after
			// the per-branch counter rewrite.
			name:          "branch 1 satisfies read",
			threshold:     32,
			payloadSize:   1 << 12,
			priming:       []primingStep{{size: 32}, {size: 16}},
			seekTo:        0,
			finalReadSize: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			payload := make([]byte, tt.payloadSize)
			for i := range payload {
				payload[i] = byte(i % 251)
			}

			// Wrap so the reader is not detected as seekable; this forces
			// the buffered/disk path through Read() instead of delegating
			// to the underlying Seeker.
			brs := NewBufferedReaderSeeker(io.MultiReader(bytes.NewReader(payload)))
			defer brs.Close()
			brs.threshold = tt.threshold

			for i, step := range tt.priming {
				buf := make([]byte, step.size)
				if _, err := io.ReadFull(brs, buf); err != nil {
					t.Fatalf("priming step %d: %v", i, err)
				}
			}

			if _, err := brs.Seek(tt.seekTo, io.SeekStart); err != nil {
				t.Fatalf("seek: %v", err)
			}

			out := make([]byte, tt.finalReadSize)
			n, err := brs.Read(out)
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("read: unexpected error: %v", err)
			}
			if n != tt.finalReadSize {
				t.Fatalf("read: got n=%d, want %d", n, tt.finalReadSize)
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
