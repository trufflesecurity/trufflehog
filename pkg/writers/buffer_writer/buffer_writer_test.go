package bufferwriter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/rand"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestBufferWriterWrite(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		input         []byte
		initialState  state
		expectedError bool
		expectedSize  int
	}{
		{
			name:         "Write in writeOnly state with empty input",
			input:        []byte(""),
			initialState: writeOnly,
		},
		{
			name:          "Write in writeOnly state with non-empty input",
			input:         []byte("hello"),
			initialState:  writeOnly,
			expectedError: false,
			expectedSize:  5,
		},
		{
			name:          "Attempt to write in readOnly state",
			input:         []byte("hello"),
			initialState:  readOnly,
			expectedError: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer := New(context.Background())
			writer.state = tc.initialState

			_, err := writer.Write(context.Background(), tc.input)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedSize, writer.Len())
			}
		})
	}
}

func BenchmarkBufferWriterWrite(b *testing.B) {
	type benchCase struct {
		name     string
		dataSize int // Size of the data to write in bytes
	}

	benchmarks := []benchCase{
		{"1KB", 1 << 10},     // 1KB
		{"4KB", 4 << 10},     // 4KB
		{"16KB", 16 << 10},   // 16KB
		{"64KB", 64 << 10},   // 64KB
		{"256KB", 256 << 10}, // 256KB
		{"1MB", 1 << 20},     // 1MB
		{"4MB", 4 << 20},     // 4MB
		{"16MB", 16 << 20},   // 16MB
		{"64MB", 64 << 20},   // 64MB
	}

	for _, bc := range benchmarks {
		bc := bc
		data := generateData(bc.dataSize) // Generate pseudo-random data for this benchmark case
		b.Run(bc.name, func(b *testing.B) {
			ctx := context.Background()
			writer := New(ctx)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := writer.Write(ctx, data)
				assert.NoError(b, err)
			}
		})
	}
}

func generateData(size int) []byte {
	rand.Seed(42)
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(rand.Intn(256))
	}
	return data
}

func TestBufferWriterReadCloser(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		initialState  state
		expectedError bool
	}{
		{
			name:          "Get ReadCloser in writeOnly state",
			initialState:  writeOnly,
			expectedError: true,
		},
		{
			name:         "Get ReadCloser in readOnly state",
			initialState: readOnly,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer := New(context.Background())
			writer.state = tc.initialState

			rc, err := writer.ReadCloser()
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, rc)

				// Test that the ReadCloser can be closed.
				err = rc.Close()
				assert.NoError(t, err)
			}
		})
	}
}

func TestBufferWriterCloseForWriting(t *testing.T) {
	writer := New(context.Background())
	err := writer.CloseForWriting()
	assert.NoError(t, err)
	assert.Equal(t, readOnly, writer.state)
}

func TestBufferWriterString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		prepareBuffer func(*BufferWriter) // Function to prepare the buffer with data or state
		expectedStr   string
		expectedError bool
	}{
		{
			name: "String with no data",
			prepareBuffer: func(_ *BufferWriter) {
				// No preparation needed, buffer is empty by default
			},
			expectedStr:   "",
			expectedError: false,
		},
		{
			name: "String with data",
			prepareBuffer: func(bw *BufferWriter) {
				_, _ = bw.Write(context.Background(), []byte("test data"))
			},
			expectedStr:   "test data",
			expectedError: false,
		},
		{
			name: "Buffer is nil",
			prepareBuffer: func(bw *BufferWriter) {
				bw.buf = nil
			},
			expectedStr:   "",
			expectedError: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer := New(context.Background())
			tc.prepareBuffer(writer)

			result, err := writer.String()
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedStr, result)
			}
		})
	}
}
