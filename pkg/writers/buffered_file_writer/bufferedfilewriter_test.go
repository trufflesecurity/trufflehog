package bufferedfilewriter

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestBufferedFileWriterNewThreshold(t *testing.T) {
	t.Parallel()

	const (
		defaultThreshold = 10 * 1024 * 1024 // 10MB
		customThreshold  = 20 * 1024 * 1024 // 20MB
	)

	tests := []struct {
		name              string
		options           []Option
		expectedThreshold uint64
	}{
		{name: "Default Threshold", expectedThreshold: defaultThreshold},
		{name: "Custom Threshold", options: []Option{WithThreshold(customThreshold)}, expectedThreshold: customThreshold},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer := New(context.Background(), tc.options...)
			assert.Equal(t, tc.expectedThreshold, writer.threshold)
			// The state should always be writeOnly when created.
			assert.Equal(t, writeOnly, writer.state)
		})
	}
}

func TestBufferedFileWriterString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		input           []byte
		expectedStr     string
		additionalInput []byte
		threshold       uint64
	}{
		{name: "Empty", input: []byte(""), expectedStr: ""},
		{name: "Nil", input: nil, expectedStr: ""},
		{name: "Small content, buffer only", input: []byte("hello"), expectedStr: "hello"},
		{
			name:        "Large content, buffer only",
			input:       []byte("longer string with more characters"),
			expectedStr: "longer string with more characters",
		},
		{
			name:        "Large content, file only",
			input:       []byte("longer string with more characters"),
			expectedStr: "longer string with more characters",
			threshold:   5,
		},
		{
			name:            "Content in both file and buffer",
			input:           []byte("initial content exceeding threshold"),
			additionalInput: []byte(" more content in buffer"),
			expectedStr:     "initial content exceeding threshold more content in buffer",
			threshold:       10, // Set a threshold that the initial content exceeds
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			writer := New(ctx, WithThreshold(tc.threshold))
			// First write, should go to file if it exceeds the threshold.
			_, err := writer.Write(ctx, tc.input)
			assert.NoError(t, err)

			// Second write, should go to buffer
			if tc.additionalInput != nil {
				_, err = writer.Write(ctx, tc.additionalInput)
				assert.NoError(t, err)
			}

			got, err := writer.String()
			assert.NoError(t, err)
			err = writer.CloseForWriting()
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedStr, got, "String content mismatch")
		})
	}
}

const (
	smallBuffer  = 2 << 5  // 64B
	mediumBuffer = 2 << 10 // 2KB
	smallFile    = 2 << 25 // 32MB
	mediumFile   = 2 << 28 // 256MB
)

func BenchmarkBufferedFileWriterString_BufferOnly_Small(b *testing.B) {
	data := bytes.Repeat([]byte("a"), smallBuffer)

	ctx := context.Background()
	writer := New(ctx)

	_, err := writer.Write(ctx, data)
	assert.NoError(b, err)

	benchmarkBufferedFileWriterString(b, writer)

	err = writer.CloseForWriting()
	assert.NoError(b, err)

	rc, err := writer.ReadCloser()
	assert.NoError(b, err)
	rc.Close()
}

func BenchmarkBufferedFileWriterString_BufferOnly_Medium(b *testing.B) {
	data := bytes.Repeat([]byte("a"), mediumBuffer)
	ctx := context.Background()
	writer := New(ctx)

	_, err := writer.Write(ctx, data)
	assert.NoError(b, err)

	benchmarkBufferedFileWriterString(b, writer)

	err = writer.CloseForWriting()
	assert.NoError(b, err)

	rc, err := writer.ReadCloser()
	assert.NoError(b, err)
	rc.Close()
}

func BenchmarkBufferedFileWriterString_OnlyFile_Small(b *testing.B) {
	data := bytes.Repeat([]byte("a"), smallFile)

	ctx := context.Background()
	writer := New(ctx)

	_, err := writer.Write(ctx, data)
	assert.NoError(b, err)

	benchmarkBufferedFileWriterString(b, writer)

	err = writer.CloseForWriting()
	assert.NoError(b, err)

	rc, err := writer.ReadCloser()
	assert.NoError(b, err)
	rc.Close()
}

func BenchmarkBufferedFileWriterString_OnlyFile_Medium(b *testing.B) {
	data := bytes.Repeat([]byte("a"), mediumFile)

	ctx := context.Background()
	writer := New(ctx)

	_, err := writer.Write(ctx, data)
	assert.NoError(b, err)

	benchmarkBufferedFileWriterString(b, writer)

	err = writer.CloseForWriting()
	assert.NoError(b, err)

	rc, err := writer.ReadCloser()
	assert.NoError(b, err)
	rc.Close()
}

func BenchmarkBufferedFileWriterString_BufferWithFile_Small(b *testing.B) {
	data := bytes.Repeat([]byte("a"), smallFile)

	ctx := context.Background()
	writer := New(ctx)

	_, err := writer.Write(ctx, data)
	assert.NoError(b, err)

	// Write again so we also fill up the buffer.
	_, err = writer.Write(ctx, data)
	assert.NoError(b, err)

	benchmarkBufferedFileWriterString(b, writer)

	err = writer.CloseForWriting()
	assert.NoError(b, err)

	rc, err := writer.ReadCloser()
	assert.NoError(b, err)
	rc.Close()
}

func BenchmarkBufferedFileWriterString_BufferWithFile_Medium(b *testing.B) {
	data := bytes.Repeat([]byte("a"), mediumFile)

	ctx := context.Background()
	writer := New(ctx)

	_, err := writer.Write(ctx, data)
	assert.NoError(b, err)

	// Write again so we also fill up the buffer.
	_, err = writer.Write(ctx, data)
	assert.NoError(b, err)

	benchmarkBufferedFileWriterString(b, writer)

	err = writer.CloseForWriting()
	assert.NoError(b, err)

	rc, err := writer.ReadCloser()
	assert.NoError(b, err)
	rc.Close()
}

func benchmarkBufferedFileWriterString(b *testing.B, w *BufferedFileWriter) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := w.String()
		assert.NoError(b, err)
	}
	b.StopTimer()
}

func TestBufferedFileWriterLen(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		input       []byte
		expectedLen int
	}{
		{name: "Empty", input: []byte(""), expectedLen: 0},
		{name: "Nil", input: nil, expectedLen: 0},
		{name: "Small content", input: []byte("hello"), expectedLen: 5},
		{name: "Large content", input: []byte("longer string with more characters"), expectedLen: 34},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer := New(context.Background())
			_, err := writer.Write(context.Background(), tc.input)
			assert.NoError(t, err)

			length := writer.Len()
			assert.Equal(t, tc.expectedLen, length)
		})
	}
}

// TestBufferedFileWriterWriteWithinThreshold tests that data is written to the buffer when the threshold
// is not exceeded.
func TestBufferedFileWriterWriteWithinThreshold(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	data := []byte("hello world")

	writer := New(ctx, WithThreshold(64))
	_, err := writer.Write(ctx, data)
	assert.NoError(t, err)

	assert.Equal(t, data, writer.buf.Bytes())
}

// TestBufferedFileWriterWriteExceedsThreshold tests that data is written to a file when the threshold
// is exceeded.
func TestBufferedFileWriterWriteExceedsThreshold(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	data := []byte("hello world")

	writer := New(ctx, WithThreshold(5))
	_, err := writer.Write(ctx, data)
	assert.NoError(t, err)

	defer func() {
		err := writer.CloseForWriting()
		assert.NoError(t, err)
	}()

	assert.NotNil(t, writer.file)
	assert.Len(t, writer.buf.Bytes(), 0)
	fileContents, err := os.ReadFile(writer.filename)
	assert.NoError(t, err)
	assert.Equal(t, data, fileContents)
}

// TestBufferedFileWriterWriteAfterFlush tests that data is written to a file when the threshold
// is exceeded, and subsequent writes are to the buffer until the threshold is exceeded again.
func TestBufferedFileWriterWriteAfterFlush(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	initialData := []byte("initial data is longer than subsequent data")
	subsequentData := []byte("subsequent data")

	// Initialize writer with a threshold that initialData will exceed.
	writer := New(ctx, WithThreshold(uint64(len(initialData)-1)))
	_, err := writer.Write(ctx, initialData)
	assert.NoError(t, err)

	defer func() {
		err := writer.CloseForWriting()
		assert.NoError(t, err)
	}()

	// Get the file modification time after the initial write.
	initialModTime, err := getFileModTime(t, writer.filename)
	assert.NoError(t, err)
	fileContents, err := os.ReadFile(writer.filename)
	assert.NoError(t, err)
	assert.Equal(t, initialData, fileContents)

	// Perform a subsequent write with data under the threshold.
	_, err = writer.Write(ctx, subsequentData)
	assert.NoError(t, err)

	assert.Equal(t, subsequentData, writer.buf.Bytes()) // Check buffer contents
	finalModTime, err := getFileModTime(t, writer.filename)
	assert.NoError(t, err)
	assert.Equal(t, initialModTime, finalModTime) // File should not be modified again
}

func getFileModTime(t *testing.T, fileName string) (time.Time, error) {
	t.Helper()

	fileInfo, err := os.Stat(fileName)
	if err != nil {
		return time.Time{}, err
	}
	return fileInfo.ModTime(), nil
}

func TestBufferedFileWriterClose(t *testing.T) {
	t.Parallel()

	const threshold = 10
	ctx := context.Background()

	tests := []struct {
		name              string
		prepareWriter     func(*BufferedFileWriter) // Function to prepare the writer for the test
		expectFileContent string
	}{
		{
			name: "No File Created, Only Buffer Data",
			prepareWriter: func(w *BufferedFileWriter) {
				// Write data under the threshold
				_, _ = w.Write(ctx, []byte("small data"))
			},
			expectFileContent: "",
		},
		{
			name: "File Created, No Data in Buffer",
			prepareWriter: func(w *BufferedFileWriter) {
				// Write data over the threshold to create a file
				_, _ = w.Write(ctx, []byte("large data is more than the threshold"))
			},
			expectFileContent: "large data is more than the threshold",
		},
		{
			name: "File Created, Data in Buffer",
			prepareWriter: func(w *BufferedFileWriter) {
				// Write data over the threshold to create a file, then write more data
				_, _ = w.Write(ctx, []byte("large data is more than the threshold"))
				_, _ = w.Write(ctx, []byte(" more data"))
			},
			expectFileContent: "large data is more than the threshold more data",
		},
		{
			name: "File Created, Buffer Cleared",
			prepareWriter: func(w *BufferedFileWriter) {
				// Write data over the threshold to create a file, then clear the buffer.
				_, _ = w.Write(ctx, []byte("large data is more than the threshold"))
				w.buf.Reset()
			},
			expectFileContent: "large data is more than the threshold",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer := New(ctx, WithThreshold(threshold))

			tc.prepareWriter(writer)

			err := writer.CloseForWriting()
			assert.NoError(t, err)

			if writer.file != nil {
				fileContents, err := os.ReadFile(writer.filename)
				assert.NoError(t, err)
				assert.Equal(t, tc.expectFileContent, string(fileContents))
				return
			}

			// If no file was created, the buffer should be empty.
			assert.Equal(t, tc.expectFileContent, "")
		})
	}
}

func TestBufferedFileWriterStateTransitionOnClose(t *testing.T) {
	t.Parallel()
	writer := New(context.Background())

	// Initially, the writer should be in write-only mode.
	assert.Equal(t, writeOnly, writer.state)

	// Perform some write operation.
	_, err := writer.Write(context.Background(), []byte("test data"))
	assert.NoError(t, err)

	// Close the writer.
	err = writer.CloseForWriting()
	assert.NoError(t, err)

	// After closing, the writer should be in read-only mode.
	assert.Equal(t, readOnly, writer.state)
}

func TestBufferedFileWriterWriteInReadOnlyState(t *testing.T) {
	t.Parallel()
	writer := New(context.Background())
	_ = writer.CloseForWriting() // Transition to read-only mode

	// Attempt to write in read-only mode.
	_, err := writer.Write(context.Background(), []byte("should fail"))
	assert.Error(t, err)
}

func BenchmarkBufferedFileWriterWriteLarge(b *testing.B) {
	ctx := context.Background()
	data := make([]byte, 1024*1024*10) // 10MB
	for i := range data {
		data[i] = byte(i % 256) // Simple pattern to avoid uniform zero data
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Threshold is smaller than the data size, data should get flushed to the file.
		writer := New(ctx, WithThreshold(1024))

		b.StartTimer()
		{
			_, err := writer.Write(ctx, data)
			assert.NoError(b, err)
		}
		b.StopTimer()

		// Ensure proper cleanup after each write operation, including closing the file
		err := writer.CloseForWriting()
		assert.NoError(b, err)

		rc, err := writer.ReadCloser()
		assert.NoError(b, err)
		rc.Close()
	}
}

func BenchmarkBufferedFileWriterWriteSmall(b *testing.B) {
	ctx := context.Background()
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256) // Simple pattern to avoid uniform zero data
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Threshold is the same as the buffer size, data should always be written to the buffer.
		writer := New(ctx, WithThreshold(1024*1024))

		b.StartTimer()
		{
			_, err := writer.Write(ctx, data)
			assert.NoError(b, err)
		}
		b.StopTimer()

		// Ensure proper cleanup after each write operation, including closing the file.
		err := writer.CloseForWriting()
		assert.NoError(b, err)

		rc, err := writer.ReadCloser()
		assert.NoError(b, err)
		rc.Close()
	}
}
